# frozen_string_literal: true

# Enforce logging output
$stdout.sync = true
$stderr.sync = true

# About
OMEJDN_LICENSE = 'Apache2.0'
OMEJDN_VERSION = File.file?('.version') ? File.read('.version').chomp : 'unknown'

puts "Starting Omejdn version #{OMEJDN_VERSION}"
puts '========================================='

require 'rubygems'
require 'bundler/setup'
require 'sinatra'
require 'sinatra/cookies'
require 'rack'
require 'cgi'
require 'securerandom'
require 'net/http'

require_relative './lib/client'
require_relative './lib/config'
require_relative './lib/user'
require_relative './lib/token'
require_relative './lib/oauth_helper'
require_relative './lib/plugins'

# A global cache, capable of storing data between calls and sessions
class Cache
  class << self; attr_accessor :authorization, :par, :public_endpoints end
  # Stores Authorization Code Metadata inbetween authorization and token retrieval
  # Contains: user, nonce, scopes, resources, claims, pkce challenge and method
  @authorization = {}
  # Stores Pushed Authorization Request Objects inbetween request push and authorization
  @par = {}
  # Stores Regex for public endpoints
  @public_endpoints = []
end

# Define endpoints using this to support fine-grained CORS
def endpoint(endpoint, methods, public_endpoint: false, &block)
  Cache.public_endpoints << (Regexp.new endpoint) if public_endpoint
  [*methods].each do |verb|
    get    endpoint, {}, &block if verb == 'GET' # Takes care of 'HEAD'
    post   endpoint, {}, &block if verb == 'POST'
    put    endpoint, {}, &block if verb == 'PUT'
    delete endpoint, {}, &block if verb == 'DELETE'
  end
end

configure do
  # Load Plugins
  PluginLoader.initialize

  config = Config.setup
  set :environment, (proc { Config.base_config['environment'].to_sym })
  enable :dump_errors, :raise_errors, :quiet
  disable :show_exceptions
  bind_ip, bind_port = config['bind_to'].split(':')
  set :bind, bind_ip
  set :port, bind_port if bind_port
  enable :sessions
  set :sessions, secure: (config['front_url'].start_with? 'https://')
  set :session_store, Rack::Session::Pool
end

def debug
  Config.base_config['environment'] != 'production'
end

def openid?(scopes)
  Config.base_config['openid'] && (scopes.include? 'openid')
end

before do
  # Sinatra does not parse multiple values to params as arrays. This line fixes this
  params.merge!(CGI.parse(request.query_string).transform_values { |v| v.length == 1 ? v[0] : v })
end

after do
  # Caching (overwrite where necessary)
  headers['Pragma'] ||= 'no-cache'
  headers['Cache-Control'] ||= 'no-store'

  # Cross Origin Resource Sharing
  if request.env.key? 'HTTP_ORIGIN' # CORS Request
    public_endpoint = Cache.public_endpoints.any? { |e| !e.match(request.path_info).nil? }
    headers['Access-Control-Allow-Origin'] = public_endpoint ? '*' : Config.base_config['front_url']
    # response.headers['Access-Control-Allow-Credentials'] = true # For some reason this throws an error
    if request.env['REQUEST_METHOD'] == 'OPTIONS' # CORS Preflight Request
      headers['Access-Control-Allow-Headers'] = request.env['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']
      headers['Access-Control-Allow-Methods'] = request.env['HTTP_ACCESS_CONTROL_REQUEST_METHOD']
      headers['Allow']                        = request.env['HTTP_ACCESS_CONTROL_REQUEST_METHOD']
      halt 204
    end
  end
end

########## TOKEN ISSUANCE ##################

# Handle token request
endpoint '/token', ['POST'], public_endpoint: true do
  resources = [*params[:resource]]
  client = OAuthHelper.authenticate_client params, env.fetch('HTTP_AUTHORIZATION', '')
  raise OAuthError.new 'invalid_request', 'Grant type not allowed' unless client.grant_type_allowed? params[:grant_type]

  PluginLoader.fire('TOKEN_STARTED', binding)
  case params[:grant_type]
  when 'client_credentials'
    scopes     = filter_scopes(client, client.filter_scopes(params[:scope]&.split) || [])
    resources  = [*Config.base_config['default_audience']] if resources.empty?
    req_claims = JSON.parse(params[:claims] || '{}')
    raise OAuthError.new 'invalid_target', "Access denied to: #{resources}" unless client.resources_allowed? resources
  when 'authorization_code'
    cache = Cache.authorization[params[:code]]
    raise OAuthError.new 'invalid_grant', 'The Authorization code was not recognized' if cache.nil?

    OAuthHelper.validate_pkce(cache[:pkce], params[:code_verifier], cache[:pkce_method]) unless cache[:pkce].nil?
    scopes     = cache[:scope]    || []
    resources  = cache[:resource] || [] if resources.empty?
    req_claims = cache[:claims]   || {}
    raise OAuthError.new 'invalid_target', "No access to: #{resources}" unless (resources - cache[:resource]).empty?
    raise OAuthError, 'invalid_request' if cache[:redirect_uri] && cache[:redirect_uri] != params[:redirect_uri]
  else
    custom_grant_type = false
    PluginLoader.fire('TOKEN_UNKNOWN_GRANT_TYPE', binding)
    raise OAuthError.new 'unsupported_grant_type', "Given: #{params[:grant_type]}" unless custom_grant_type
  end
  raise OAuthError.new 'access_denied', 'No scopes granted' if scopes.empty?

  front_url = Config.base_config['front_url']
  resources << ("#{front_url}/userinfo") if openid?(scopes)
  resources << ("#{front_url}/api") unless scopes.select { |s| s.start_with? 'omejdn:' }.empty?

  OAuthHelper.adapt_requested_claims req_claims

  user = cache&.dig(:user)
  nonce = cache&.dig(:nonce)
  id_token = Token.id_token client, user, scopes, req_claims, nonce if openid?(scopes)
  access_token = Token.access_token client, user, scopes, req_claims, resources
  response = {
    access_token: access_token,
    id_token: id_token,
    expires_in: Config.base_config.dig('access_token', 'expiration'),
    token_type: 'bearer',
    scope: (scopes.join ' ')
  }
  PluginLoader.fire('TOKEN_FINISHED', binding)
  # Delete the authorization code as it is single use
  Cache.authorization.delete(params[:code])
  halt 200, { 'Content-Type' => 'application/json' }, response.compact.to_json
rescue OAuthError => e
  halt 400, { 'Content-Type' => 'application/json' }, e.to_s
end

########## AUTHORIZATION CODE FLOW ##################

def auth_response(auth, response_params)
  auth ||= {}
  response_params = {
    iss: Config.base_config['issuer'],
    state: auth[:state]
  }.merge(response_params).compact
  PluginLoader.fire('AUTHORIZATION_FINISHED', binding)
  halt 400, (haml :error, locals: { error: response_params }) if auth[:redirect_uri].nil?
  case auth[:response_mode]
  when 'form_post'
    halt 200, (haml :form_post_response, locals: { redirect_uri: auth[:redirect_uri], params: response_params })
  when 'fragment'
    redirect to("#{auth[:redirect_uri]}##{URI.encode_www_form response_params}")
  else # 'query' and unsupported types
    redirect to("#{auth[:redirect_uri]}?#{URI.encode_www_form response_params}")
  end
end

def filter_scopes(resource_owner, scopes)
  scope_mapping = Config.scope_mapping_config
  scopes.select do |s|
    if s == 'openid'
      true
    elsif s.include? ':'
      key, value = s.split(':', 2)
      resource_owner.claim?(key, value)
    else
      (scope_mapping[s] || []).any? { |claim| resource_owner.claim?(claim) }
    end
  end
end

# Pushed Authorization Requests
endpoint '/par', ['POST'], public_endpoint: true do
  raise OAuthError.new 'invalid_request', 'Request URI not supported here' if params.key(:request_uri)

  client = OAuthHelper.authenticate_client params, env.fetch('HTTP_AUTHORIZATION', '')
  OAuthHelper.prepare_params params, client

  uri = "urn:ietf:params:oauth:request_uri:#{SecureRandom.uuid}"
  Cache.par[uri] = params # TODO: Expiration
  PluginLoader.fire('AUTHORIZATION_PAR', binding)
  halt 201, { 'Content-Type' => 'application/json' }, { 'request_uri' => uri, 'expires_in' => 60 }.to_json
rescue OAuthError => e
  halt 400, { 'Content-Type' => 'application/json' }, e.to_s
end

# Handle authorization request
endpoint '/authorize', ['GET'], public_endpoint: true do
  # Initial sanity checks and request object resolution
  client = Client.find_by_id params[:client_id]
  raise OAuthError.new 'invalid_client', 'Client unknown' if client.nil?

  # Generate new authorization code and aggregate data about the request
  # Any inputs to members not starting in req_ are sufficiently sanitized
  # Note that some values are reassigned after dealing with request and request_uri
  session[:current_auth] = SecureRandom.uuid
  Cache.authorization[session[:current_auth]] = auth = {
    client: client, # The requesting client
    state: params[:state], # Client state
    nonce: params[:nonce], # The client's OIDC nonce
    response_mode: params[:response_mode] # The response mode to use
  }

  # Used for error messages, might be overwritten by request objects
  auth[:redirect_uri] = client.verify_redirect_uri params[:redirect_uri], true if params[:redirect_uri]
  OAuthHelper.prepare_params params, client
  uri = client.verify_redirect_uri params[:redirect_uri], openid?((params[:scope] || '').split) # For real this time

  # Some of these values may have been overwritten
  auth.merge!({
                state: params[:state], # Client state
                nonce: params[:nonce], # The client's OIDC nonce
                response_mode: params[:response_mode] # The response mode to use
              })

  raise OAuthError.new 'invalid_scope', 'No scope specified' unless params[:scope] # We require specifying the scope
  raise OAuthError.new 'unsupported_response_type', 'Only code supported' unless params[:response_type] == 'code'
  if !params[:code_challenge].nil? && params[:code_challenge_method] != 'S256'
    raise OAuthError.new 'invalid_request', 'Transform algorithm not supported'
  end

  auth.merge!({
                redirect_uri: uri,
                pkce: params[:code_challenge],
                pkce_method: params[:code_challenge_method],
                req_scope: params[:scope].split,
                req_claims: JSON.parse(params[:claims] || '{}'),
                req_resource: params['resource']
              })

  auth[:req_max_age] = params[:max_age]
  auth[:req_tasks] = params[:prompt]&.split&.uniq || []
  if (auth[:req_tasks].include? 'none') && auth[:req_tasks] != ['none']
    raise OAuthError.new 'invalid_request', "Invalid 'prompt' values: #{params[:prompt]}"
  end

  PluginLoader.fire('AUTHORIZATION_STARTED', binding)
  redirect to("#{Config.base_config['front_url']}/login")
rescue OAuthError => e
  auth_response Cache.authorization[session[:current_auth]], e.to_h
end

########## CONSENT ##################

endpoint '/consent', ['GET'] do
  auth = Cache.authorization[session[:current_auth]]

  redirect to("#{Config.base_config['front_url']}/login") if (user = auth[:user]).nil? # Require Login for this step
  raise OAuthError.new 'invalid_client', 'Client unknown' if (client = auth[:client]).nil?

  # Find the right scopes
  auth[:scope] = filter_scopes(user, client.filter_scopes(auth[:req_scope]))
  auth[:claims] = auth[:req_claims]
  auth[:resource] = [auth[:req_resource] || Config.base_config['default_audience']].flatten
  raise OAuthError.new 'invalid_target', 'Resources not granted' unless client.resources_allowed? auth[:resource]

  p "Granted scopes: #{auth[:scope]}"
  p "The user seems to be #{user.username}" if debug

  # Is consent required?
  consent_required = auth[:req_tasks].include? 'consent'
  consent_required ||= !(auth[:scope] - (user.consent&.dig(client.client_id) || [])).empty?
  auth_response auth, { code: session[:current_auth] } unless consent_required # Shortcut
  raise OAuthError, 'consent_required' if auth[:req_tasks].include? 'none'

  PluginLoader.fire('AUTHORIZATION_CONSENT_STARTED', binding)
  return haml :consent, locals: {
    host: Config.base_config['front_url'],
    user: user,
    client: client,
    scopes: auth[:scope],
    scope_description: Config.scope_description_config
  }
rescue OAuthError => e
  auth_response Cache.authorization[session[:current_auth]], e.to_h
end

endpoint '/consent/exec', ['POST'] do
  auth = Cache.authorization[session[:current_auth]]
  redirect to("#{Config.base_config['front_url']}/login") if (user = auth[:user]).nil? # Require Login for this step
  (user.consent ||= {})[auth[:client].client_id] = auth[:scope]
  PluginLoader.fire('AUTHORIZATION_CONSENT_FINISHED', binding)
  user.save
  auth_response auth, { code: session[:current_auth] }
rescue OAuthError => e
  auth_response Cache.authorization[session[:current_auth]], e.to_h
end

########## LOGIN/LOGOUT ##################

# OpenID Connect RP-Initiated Logout 1.0
endpoint '/logout', ['GET', 'POST'], public_endpoint: true do
  id_token = Token.decode params[:id_token_hint]
  client = Client.find_by_id id_token&.dig('aud')
  redirect_uri = client&.verify_post_logout_redirect_uri params[:post_logout_redirect_uri]
  PluginLoader.fire('LOGOUT_STARTED', binding)
  halt 200, (haml :logout, locals: { state: params[:state], redirect_uri: redirect_uri })
rescue StandardError
  halt 400
end

endpoint '/logout/exec', ['POST'] do
  session.delete(:user) # TODO: log out the specified user only
  redirect_uri = "#{Config.base_config['front_url']}/login"
  redirect_uri = params[:redirect_uri] + (params[:state] || '') if params[:redirect_uri]
  PluginLoader.fire('LOGOUT_FINISHED', binding)
  redirect to(redirect_uri)
end

# Call this function to end the login process
def login_finished(user, authenticated, remember_me: false)
  auth = Cache.authorization[session[:current_auth]]
  user.auth_time = Time.new.to_i if authenticated
  PluginLoader.fire('AUTHORIZATION_LOGIN_FINISHED', binding)
  user.save
  auth[:user] = user
  session[:user] = user.username if remember_me
  redirect to("#{Config.base_config['front_url']}/consent")
end

endpoint '/login', ['GET'] do
  # Is login required?
  auth = Cache.authorization[session[:current_auth]]
  login_required = session[:user].nil? || !(%w[login select_account] & auth[:req_tasks]).empty?
  login_required ||= (user = User.find_by_id session[:user]).nil?
  login_required ||= auth[:req_max_age] && (Time.new.to_i - user.auth_time) > auth[:req_max_age].to_i
  login_finished user, false unless login_required
  raise OAuthError, 'login_required' if auth[:req_tasks].include? 'none'

  login_options = []
  PluginLoader.fire('AUTHORIZATION_LOGIN_STARTED', binding)
  halt 200, (haml :login, locals: {
    no_password_login: (Config.base_config['no_password_login'] || false),
    host: Config.base_config['front_url'],
    login_options: login_options
  })
rescue OAuthError => e
  auth_response Cache.authorization[session[:current_auth]], e.to_h
end

endpoint '/login/exec', ['POST'] do
  user = User.find_by_id params[:username]
  redirect to("#{Config.base_config['front_url']}/login?incorrect") unless user&.verify_password(params[:password])
  login_finished user, true, remember_me: true
rescue OAuthError => e
  auth_response Cache.authorization[session[:current_auth]], e.to_h
end

########## USERINFO ##################

endpoint '/userinfo', ['GET', 'POST'], public_endpoint: true do
  token  = Token.decode env.fetch('HTTP_AUTHORIZATION', '')&.slice(7..-1), '/userinfo'
  client = Client.find_by_id token['client_id']
  user   = User.find_by_id   token['sub']
  halt 401 unless user && client
  req_claims = token.dig('omejdn_reserved', 'userinfo_req_claims')
  userinfo = OAuthHelper.map_claims_to_userinfo(user.attributes, req_claims, client, token['scope'].split)
  userinfo['sub'] = user.username
  PluginLoader.fire('OPENID_USERINFO', binding)
  halt 200, { 'Content-Type' => 'application/json' }, userinfo.to_json
rescue StandardError => e
  p e if debug
  halt 401
end

########## WELL-KNOWN ENDPOINTS ##################

before '/(.well-known*|jwks.json)' do
  headers['Cache-Control'] = "public, max-age=#{60 * 60 * 24}, must-revalidate"
  headers.delete('Pragma')
end

endpoint '/.well-known/(oauth-authorization-server|openid-configuration)', ['GET'], public_endpoint: true do
  metadata = OAuthHelper.configuration_metadata
  PluginLoader.fire('STATIC_METADATA', binding)
  halt 200, { 'Content-Type' => 'application/json' }, (OAuthHelper.sign_metadata metadata).to_json
end

endpoint '/.well-known/webfinger', ['GET'], public_endpoint: true do
  res = CGI.unescape((params[:resource] || '').gsub('%20', '+'))
  halt 400 unless res.start_with? 'acct:'
  halt 404 if Config.webfinger_config.filter { |h| res.end_with? h }.empty?
  webfinger = {
    subject: res,
    properties: {},
    links: [{
      rel: 'http://openid.net/specs/connect/1.0/issuer',
      href: Config.base_config['issuer']
    }]
  }
  PluginLoader.fire('STATIC_WEBFINGER', binding)
  halt 200, { 'Content-Type' => 'application/json' }, webfinger.to_json
end

endpoint '/jwks.json', ['GET'], public_endpoint: true do
  jwks = Keys.generate_jwks
  PluginLoader.fire('STATIC_JWKS', binding)
  halt 200, { 'Content-Type' => 'application/json' }, jwks.to_json
end

endpoint '/about', ['GET'], public_endpoint: true do
  about = { 'version' => OMEJDN_VERSION, 'license' => OMEJDN_LICENSE }
  PluginLoader.fire('STATIC_ABOUT', binding)
  halt 200, { 'Content-Type' => 'application/json' }, about.to_json
end

# Optionally create admin
Config.create_admin
