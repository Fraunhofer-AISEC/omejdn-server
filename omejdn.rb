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
  class << self; attr_accessor :user_session, :authorization, :par, :public_endpoints end
  # Stores User Sessions. We probably want to use a KV-store at some point
  @user_session = {}
  # Stores Authorization Code Metadata inbetween authorization and token retrieval
  # Contains: user, nonce, scopes, resources, claims, pkce challenge and method
  @authorization = {}
  # Stores Pushed Authorization Request Objects inbetween request push and authorization
  @par = {}
  # Stores Regex for public endpoints
  @public_endpoints = []
end

configure do
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
      headers['Access-Control-Allow-Methods'] = request.env['HTTP_ACCESS_CONTROL_REQUEST_METHODS']
      headers['Allow']                        = request.env['HTTP_ACCESS_CONTROL_REQUEST_METHODS']
      halt 204
    end
  end
end

def debug
  Config.base_config['environment'] != 'production'
end

def openid?(scopes)
  Config.base_config['openid'] && (scopes.include? 'openid')
end

########## TOKEN ISSUANCE ##################

# Handle token request
endpoint '/token', ['POST'], public_endpoint: true do
  resources = [*params[:resource]]
  client = OAuthHelper.authenticate_client params, env.fetch('HTTP_AUTHORIZATION', '')
  raise OAuthError.new 'invalid_request', 'Grant type not allowed' unless client.grant_type_allowed? params[:grant_type]

  case params[:grant_type]
  when 'client_credentials'
    scopes     = filter_scopes(client, client.filter_scopes(params[:scope]&.split) || [])
    resources  = [Config.base_config['default_audience']] if resources.empty?
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
    raise OAuthError.new 'unsupported_grant_type', "Given: #{params[:grant_type]}"
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
  # Delete the authorization code as it is single use
  Cache.authorization.delete(params[:code])
  halt 200, { 'Content-Type' => 'application/json' }, {
    access_token: access_token,
    id_token: id_token,
    expires_in: Config.base_config.dig('access_token', 'expiration'),
    token_type: 'bearer',
    scope: (scopes.join ' ')
  }.compact.to_json
rescue OAuthError => e
  halt 400, { 'Content-Type' => 'application/json' }, e.to_s
end

########## AUTHORIZATION FLOW ##################

# Defines tasks for the user before a code is issued
module AuthorizationTask
  ACCOUNT_SELECT = 1
  LOGIN = 2
  CONSENT = 3
  ISSUE = 4
end

# Redirect to the current task.
# completed_task will be removed from the list
def next_task(completed_task = nil)
  auth = Cache.authorization[session[:current_auth]]
  tasklist = auth[:tasks]
  tasklist ||= []
  tasklist.delete(completed_task) unless completed_task.nil?
  tasklist.sort!.uniq!
  case tasklist.first
  when AuthorizationTask::ACCOUNT_SELECT
    # FIXME: Provide a way to choose the current account without requiring another login
    tasklist[0] = AuthorizationTask::LOGIN
    tasklist.uniq!
    next_task
  when AuthorizationTask::LOGIN
    redirect to("#{Config.base_config['front_url']}/login")
  when AuthorizationTask::CONSENT
    redirect to("#{Config.base_config['front_url']}/consent")
  when AuthorizationTask::ISSUE
    # Only issue code once
    tasklist.shift
    auth_response auth, { code: session[:current_auth] }
  end
  # The user has jumped into some stage without an initial /authorize call
  # For now, redirect to /login
  p "Undefined task: #{task}. Redirecting to /login"
  redirect to("#{Config.base_config['front_url']}/login")
end

# Pushed Authorization Requests
endpoint '/par', ['POST'], public_endpoint: true do
  raise OAuthError.new 'invalid_request', 'Request URI not supported here' if params.key(:request_uri)

  client = OAuthHelper.authenticate_client params, env.fetch('HTTP_AUTHORIZATION', '')
  OAuthHelper.prepare_params params, client

  uri = "urn:ietf:params:oauth:request_uri:#{SecureRandom.uuid}"
  Cache.par[uri] = params # TODO: Expiration
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
  session[:current_auth] = SecureRandom.uuid
  Cache.authorization[session[:current_auth]] = cache = {
    client_id: client.client_id, # The requesting client
    state: params[:state], # Client state
    nonce: params[:nonce], # The client's OIDC nonce
    response_mode: params[:response_mode], # The response mode to use
    tasks: [] # Tasks the user has to perform
  }

  # Used for error messages, might be overwritten by request objects
  cache[:redirect_uri] = client.verify_redirect_uri params[:redirect_uri], true if params[:redirect_uri]
  OAuthHelper.prepare_params params, client
  uri = client.verify_redirect_uri params[:redirect_uri], openid?((params[:scope] || '').split) # For real this time

  raise OAuthError.new 'invalid_scope', 'No scope specified' unless params[:scope] # We require specifying the scope
  raise OAuthError.new 'unsupported_response_type', 'Only code supported' unless params[:response_type] == 'code'
  if !params[:code_challenge].nil? && params[:code_challenge_method] != 'S256'
    raise OAuthError.new 'invalid_request', 'Transform algorithm not supported'
  end

  cache.merge!({
                 redirect_uri: uri,
                 pkce: params[:code_challenge],
                 pkce_method: params[:code_challenge_method],
                 req_scope: params[:scope].split,
                 req_claims: JSON.parse(params[:claims] || '{}'),
                 req_resource: params['resource']
               })

  # We first define a minimum set of acceptable tasks
  if session[:user].nil? # User not yet logged in
    cache[:tasks] << AuthorizationTask::LOGIN
    cache[:tasks] << AuthorizationTask::CONSENT
  else
    user = Cache.user_session[session[:user]]
    update_auth_scope cache, user, client
    # If consent is not yet given to the client, demand it
    if (cache[:scope] - (session.dig(:consent, client.client_id) || [])).empty?
      cache[:user] = user
    else
      cache[:tasks] << AuthorizationTask::CONSENT
    end
  end

  # The client may request some tasks on his own
  # Strictly speaking, this is OIDC only, but there is no harm in supporting it for plain OAuth,
  # since a client can at most require additional actions
  params[:prompt]&.split&.each do |task|
    case task
    when 'none'
      raise OAuthError, 'account_selection_required' if cache[:tasks].include? AuthorizationTask::ACCOUNT_SELECT
      raise OAuthError, 'login_required'             if cache[:tasks].include? AuthorizationTask::LOGIN
      raise OAuthError, 'consent_required'           if cache[:tasks].include? AuthorizationTask::CONSENT
      raise OAuthError.new 'invalid_request', "Invalid 'prompt' values: #{params[:prompt]}" if params[:prompt] != 'none'
    when 'login'
      cache[:tasks] << AuthorizationTask::LOGIN
    when 'consent'
      cache[:tasks] << AuthorizationTask::CONSENT
    when 'select_account'
      cache[:tasks] << AuthorizationTask::ACCOUNT_SELECT
    end
  end
  if params[:max_age] && session[:user] &&
     (Time.new.to_i - Cache.user_session[session[:user]].auth_time) > params[:max_age].to_i
    cache[:tasks] << AuthorizationTask::LOGIN
  end

  # Redirect the user to start the authentication flow
  cache[:tasks] << AuthorizationTask::ISSUE
  next_task
rescue OAuthError => e
  auth_response Cache.authorization[session[:current_auth]], e.to_h
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

def update_auth_scope(auth, user, client)
  # Find the right scopes
  auth[:scope] = filter_scopes(user, client.filter_scopes(auth[:req_scope]))
  p "Granted scopes: #{auth[:scope]}"
  p "The user seems to be #{user.username}" if debug

  auth[:claims] = auth[:req_claims]
  auth[:resource] = [auth[:req_resource] || Config.base_config['default_audience']].flatten
  raise OAuthError.new 'invalid_target', 'Resources not granted' unless client.resources_allowed? auth[:resource]
end

endpoint '/consent', ['GET'] do
  auth = Cache.authorization[session[:current_auth]]
  if session[:user].nil?
    auth[:tasks].unshift AuthorizationTask::LOGIN
    next_task
  end

  user = Cache.user_session[session[:user]]
  raise OAuthError.new 'invalid_user', 'User session invalid' if user.nil?

  client = Client.find_by_id auth[:client_id]
  raise OAuthError.new 'invalid_client', 'Client unknown' if client.nil?

  # Seems to be in order
  return haml :authorization_page, locals: {
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
  session[:consent] ||= {}
  session[:consent][auth[:client_id]] = auth[:scope]
  auth[:user] = Cache.user_session[session[:user]]
  next_task AuthorizationTask::CONSENT
rescue OAuthError => e
  auth_response Cache.authorization[session[:current_auth]], e.to_h
end

def auth_response(auth, response_params)
  auth ||= {}
  response_params = {
    iss: Config.base_config['issuer'],
    state: auth[:state]
  }.merge(response_params).compact
  halt 400, response_params.to_json if auth[:redirect_uri].nil?
  case auth[:response_mode]
  when 'form_post'
    halt 200, (haml :form_post_response, locals: { redirect_uri: auth[:redirect_uri], params: response_params })
  when 'fragment'
    redirect to("#{auth[:redirect_uri]}##{URI.encode_www_form response_params}")
  else # 'query' and unsupported types
    redirect to("#{auth[:redirect_uri]}?#{URI.encode_www_form response_params}")
  end
end

########## USERINFO ##################

endpoint '/userinfo', ['GET', 'POST'], public_endpoint: true do
  token = Token.decode env.fetch('HTTP_AUTHORIZATION', '')&.slice(7..-1), '/userinfo'
  client = Client.find_by_id token['client_id']
  user = User.find_by_id(token['sub'])
  halt 401 if user.nil?
  req_claims = token.dig('omejdn_reserved', 'userinfo_req_claims')
  userinfo = OAuthHelper.map_claims_to_userinfo(user.attributes, req_claims, client, token['scope'].split)
  userinfo['sub'] = user.username
  halt 200, { 'Content-Type' => 'application/json' }, userinfo.to_json
rescue StandardError => e
  p e if debug
  halt 401
end

########## LOGIN/LOGOUT ##################

# OpenID Connect RP-Initiated Logout 1.0
endpoint '/logout', ['GET', 'POST'], public_endpoint: true do
  id_token = Token.decode params[:id_token_hint]
  client = Client.find_by_id id_token&.dig('aud')
  halt 200, (haml :logout, locals: {
    state: params[:state],
    redirect_uri: (client&.verify_post_logout_redirect_uri params[:post_logout_redirect_uri]),
    user: ((User.find_by_id id_token&.dig('sub')) || Cache.user_session[session[:user]])
  })
rescue StandardError
  halt 400
end

endpoint '/logout/exec', ['POST'] do
  session.delete(:user) # TODO: log out the specified user only
  redirect_uri = "#{Config.base_config['front_url']}/login"
  redirect_uri = params[:redirect_uri] + (params[:state] || '') if params[:redirect_uri]
  redirect to(redirect_uri)
end

# FIXME
# This should use a more generic way to select the OP to use
endpoint '/login', ['GET'] do
  providers = Config.oauth_provider_config&.map do |provider|
    url = URI(provider['authorization_endpoint'])
    url.query = URI.encode_www_form({
                                      client_id: provider['client_id'],
                                      scope: provider['scopes'],
                                      redirect_uri: provider['redirect_uri'],
                                      response_type: provider['response_type']
                                    })
    { url: url.to_s, name: provider['name'], logo: provider['logo'] }
  end
  halt 200, (haml :login, locals: {
    no_password_login: (Config.base_config['no_password_login'] || false),
    host: Config.base_config['front_url'],
    providers: providers
  })
end

endpoint '/login/exec', ['POST'] do
  user = User.find_by_id(params[:username])
  unless user&.verify_password(params[:password])
    redirect to("#{Config.base_config['front_url']}/login?error=\"Credentials incorrect\"")
  end
  user.auth_time = Time.new.to_i
  session[:user] = SecureRandom.uuid
  Cache.user_session[session[:user]] = user
  auth = Cache.authorization[session[:current_auth]]
  auth[:user] = user
  update_auth_scope auth, user, (Client.find_by_id auth[:client_id])
  next_task AuthorizationTask::LOGIN
rescue OAuthError => e
  auth_response Cache.authorization[session[:current_auth]], e.to_h
end

# FIXME
# This should also be more generic and use the correct OP
endpoint '/oauth_cb', ['GET'], public_endpoint: true do
  oauth_providers = Config.oauth_provider_config
  provider = oauth_providers.select { |pv| pv['name'] == params[:provider] }.first

  at = nil
  uri = URI(provider['token_endpoint'])
  Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
    req = Net::HTTP::Post.new(uri)
    req.set_form_data('code' => params[:code],
                      'client_id' => provider['client_id'],
                      'client_secret' => provider['client_secret'],
                      'grant_type' => 'authorization_code',
                      'redirect_uri' => provider['redirect_uri'])
    res = http.request req
    at = JSON.parse(res.body)['access_token']
  end
  return 'Unauthorized' if at.nil?

  user = nil
  uri = URI(provider['userinfo_endpoint'])
  Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
    req = Net::HTTP::Get.new(uri)
    req['Authorization'] = "Bearer #{at}"
    res = http.request req
    user = User.generate_extern_user(provider, JSON.parse(res.body))
  end
  return 'Internal Error' if user.username.nil?

  user.auth_time = Time.new.to_i
  session[:user] = SecureRandom.uuid
  Cache.user_session[session[:user]] = user
  auth = Cache.authorization[session[:current_auth]]
  update_auth_scope auth, user, (Client.find_by_id auth[:client_id])
  next_task AuthorizationTask::LOGIN
end

########## WELL-KNOWN ENDPOINTS ##################

before '/(.well-known*|jwks.json)' do
  headers['Cache-Control'] = "public, max-age=#{60 * 60 * 24}, must-revalidate"
  headers.delete('Pragma')
end

endpoint '/.well-known/(oauth-authorization-server|openid-configuration)', ['GET'], public_endpoint: true do
  halt 200, { 'Content-Type' => 'application/json' }, OAuthHelper.configuration_metadata.to_json
end

endpoint '/.well-known/webfinger', ['GET'], public_endpoint: true do
  res = CGI.unescape((params[:resource] || '').gsub('%20', '+'))
  halt 400 unless res.start_with? 'acct:'
  halt 404 if Config.webfinger_config.filter { |h| res.end_with? h }.empty?
  halt 200, { 'Content-Type' => 'application/json' }, {
    subject: res,
    properties: {},
    links: [{
      rel: 'http://openid.net/specs/connect/1.0/issuer',
      href: Config.base_config['issuer']
    }]
  }.to_json
end

endpoint '/jwks.json', ['GET'], public_endpoint: true do
  halt 200, { 'Content-Type' => 'application/json' }, Keys.generate_jwks.to_json
end

endpoint '/about', ['GET'], public_endpoint: true do
  halt 200, { 'Content-Type' => 'application/json' }, {
    'version' => OMEJDN_VERSION,
    'license' => OMEJDN_LICENSE
  }.to_json
end

# Load all Plugins and optionally create admin
PluginLoader.initialize
Config.create_admin
