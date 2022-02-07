# frozen_string_literal: true

# Enforce logging output
$stdout.sync = true
$stderr.sync = true

require 'rubygems'
require 'bundler/setup'
require 'rack'
require 'cgi'
require 'sinatra'
require 'sinatra/cookies'
# require 'sinatra/cors'
require 'sinatra/activerecord'
require 'securerandom'
require 'json/jwt'
require 'webrick'
require 'webrick/https'
require 'net/http'

require_relative './lib/client'
require_relative './lib/config'
require_relative './lib/user'
require_relative './lib/token'
require_relative './lib/oauth_helper'
require_relative './lib/plugins'

OMEJDN_LICENSE = 'Apache2.0'

def version
  return File.read('.version').chomp if File.file? '.version'

  'unknown'
end

def debug
  Config.base_config['app_env'] != 'production'
end

def openid?(scopes)
  Config.base_config['openid'] && (scopes.include? 'openid')
end

def apply_env(config, conf_key, fallback)
  conf_parts = conf_key.split('.')
  env_value = ENV["OMEJDN_#{conf_parts.join('__').upcase}"]
  conf_key = conf_parts.pop
  conf_parts.each do |part|
    config[part] ||= {}
    config = config[part]
  end
  env_value = env_value.to_i if begin
    Integer(env_value)
  rescue StandardError
    false
  end
  env_value = false if env_value == 'false'
  env_value = true if env_value == 'true'
  config[conf_key] = env_value || config[conf_key] || fallback
end

configure do
  # account for environment overrides
  config = Config.base_config
  apply_env(config, 'issuer',           'https://localhost:4567')
  apply_env(config, 'front_url',        config['issuer'])
  apply_env(config, 'bind_to',          '0.0.0.0:4567')
  apply_env(config, 'allow_origin',     '*')
  apply_env(config, 'app_env',          'debug')
  apply_env(config, 'openid',           false)
  apply_env(config, 'default_audience', '')
  apply_env(config, 'accept_audience',  config['issuer'])
  %w[access_token id_token].each do |token|
    apply_env(config, "#{token}.expiration", 3600)
    apply_env(config, "#{token}.algorithm",  'RS256')
  end
  has_user_db_configured = config.dig('plugins', 'user_db') && !config.dig('plugins', 'user_db').empty?
  if config['openid'] && !has_user_db_configured
    puts 'ERROR: No user_db plugin defined. Cannot serve OpenID functionality'
    exit
  end
  apply_env(config, 'user_backend_default', config.dig('plugins', 'user_db').keys.first) if has_user_db_configured
  Config.base_config = config

  # Initialize admin user if given in ENV
  if ENV['OMEJDN_ADMIN']
    admin_name, admin_pw = ENV['OMEJDN_ADMIN'].split(':')
    admin = User.find_by_id(admin_name)
    if admin
      admin.update_password(admin_pw)
    else
      admin = User.from_dict({
                               'username' => admin_name,
                               'attributes' => [{ 'key' => 'omejdn', 'value' => 'admin' }],
                               'password' => admin_pw
                             })
      User.add_user(admin, config['user_backend_default'])
    end
  end

  # Easier debugging for local tests
  set :raise_errors, debug && !ENV['HOST']
  set :show_exceptions, debug && ENV['HOST']
  bind_ip, bind_port = config['bind_to'].split(':')
  set :bind, bind_ip
  set :port, bind_port if bind_port
  enable :sessions
  set :sessions, secure: (config['front_url'].start_with? 'https://')
  set :session_store, Rack::Session::Pool

  set :allow_origin, config['allow_origin']
  set :allow_methods, 'GET,HEAD,POST,PUT,DELETE'
  set :allow_headers, 'content-type,if-modified-since, authorization'
  set :expose_headers, 'location,link'
  set :allow_credentials, true
end

# Stores User Sessions. We probably want to use a KV-store at some point
class UserSession
  @user_session = {}
  def self.get
    @user_session
  end
end

# Stores Authorization Code Metadata inbetween authorization and token retrieval
# Contains: user, nonce, scopes, resources, claims, pkce challenge and method
class AuthorizationCache
  @request_cache = {}
  def self.get
    @request_cache
  end
end

# Stores Pushed Authorization Request Objects inbetween request push and authorization
class PARCache
  @cache = {}
  def self.get
    @cache
  end
end

before do
  # We define global cache control headers here
  # They may be overwritten where necessary
  headers['Pragma'] = 'no-cache'
  headers['Cache-Control'] = 'no-store'
  headers['Access-Control-Allow-Origin'] = Config.base_config['allow_origin']
  headers['Access-Control-Allow-Headers'] = 'content-type,if-modified-since, authorization'
  if request.env['REQUEST_METHOD'] == 'OPTIONS'
    options = (%w[HEAD GET POST PUT DELETE].reject do |verb|
      settings.routes[verb].select { |r, _c, _b| request.path_info == '*' || !r.match(request.path_info).nil? }.empty?
    end)
    halt 404 if options.empty?
    headers['Allow'] = options.join(',')
    headers['Access-Control-Allow-Methods'] = options.join(',')
    headers['Content-Type'] ||= 'text/html'
    halt 200, options.join(',')
  end
  # Sinatra does not parse multiple values to params as arrays.
  # This line fixes this
  params.merge!(CGI.parse(request.query_string).transform_values { |v| v.length == 1 ? v[0] : v })

  return if request.get_header('HTTP_ORIGIN').nil?
  unless request.get_header('HTTP_ORIGIN').start_with?('chrome-extension://') ||
         request.get_header('HTTP_ORIGIN').start_with?('moz-extension://')
    return
  end
end

########## TOKEN ISSUANCE ##################

# Handle token request
post '/token' do
  resources = [*params[:resource]]

  case params[:grant_type]
  when 'client_credentials'
    client = OAuthHelper.identify_client params, authenticate: true
    scopes = client.filter_scopes(params[:scope]&.split) || []
    resources = [Config.base_config['default_audience']] if resources.empty?
    req_claims = JSON.parse(params[:claims] || '{}')
    raise OAuthError.new 'invalid_target', "Access denied to: #{resources}" unless client.resources_allowed? resources
  when 'authorization_code'
    cache = AuthorizationCache.get[params[:code]]
    raise OAuthError.new 'invalid_code', 'The Authorization code was not recognized' if cache.nil?

    OAuthHelper.validate_pkce(cache[:pkce], params[:code_verifier], cache[:pkce_method]) unless cache[:pkce].nil?
    client = OAuthHelper.identify_client params, authenticate: false
    scopes = client.filter_scopes(params[:scope]&.split)
    scopes = cache[:scopes] || [] if scopes.empty?
    resources = cache[:resources] if resources.empty?
    req_claims = cache[:claims] || {}
    req_claims = JSON.parse params[:claims] if params[:claims]
    raise OAuthError.new 'invalid_scope', 'Ungranted scopes requested' unless (scopes - cache[:scopes]).empty?
    raise OAuthError.new 'invalid_target', "No access to: #{resources}" unless (resources - cache[:resources]).empty?
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
  AuthorizationCache.get.delete(params[:code])
  halt 200, (OAuthHelper.token_response access_token, scopes, id_token)
rescue OAuthError => e
  halt 400, e.to_s
end

after '/token' do
  headers['Content-Type'] = 'application/json'
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
  session[:tasks] ||= []
  session[:tasks].delete(completed_task) unless completed_task.nil?
  task = session[:tasks].first
  case task
  when AuthorizationTask::ACCOUNT_SELECT
    # FIXME: Provide a way to choose the current account without requiring another login
    session[:tasks][0] = AuthorizationTask::LOGIN
    session[:tasks].uniq!
    next_task
  when AuthorizationTask::LOGIN
    redirect to("#{Config.base_config['front_url']}/login")
  when AuthorizationTask::CONSENT
    redirect to("#{Config.base_config['front_url']}/consent")
  when AuthorizationTask::ISSUE
    # Only issue code once
    session[:tasks].delete(task)
    issue_code
  end
  # The user has jumped into some stage without an initial /authorize call
  # For now, redirect to /login
  p "Undefined task: #{task}. Redirecting to /login"
  redirect to("#{Config.base_config['front_url']}/login")
end

def handle_auth_error(error)
  # Try to determine the response_url to send the error to.
  response_url = session[:redirect_uri_verified]
  halt 400, error.to_s if response_url.nil?
  query = []
  query << "state=#{session.dig(:url_params, :state)}" unless session.dig(:url_params, :state).nil?
  query << "error=#{error.type}"
  query << "error_description=#{error.description}"
  query << "iss=#{Config.base_config['issuer']}"
  redirect to "#{response_url}?#{query.join '&'}"
end

# Pushed Authorization Requests
post '/par' do
  raise OAuthError.new 'invalid_request', 'Request URI not supported here' if params.key(:request_uri)

  client = OAuthHelper.identify_client params, authenticate: false
  OAuthHelper.prepare_params params, client

  uri = "urn:ietf:params:oauth:request_uri:#{SecureRandom.uuid}"
  PARCache.get[uri] = params
  headers['Content-Type'] = 'application/json'
  halt 201, { 'request_uri' => uri, 'expires_in' => 60 }.to_json # TODO: Expiration
rescue OAuthError => e
  halt 400, e.to_s
end

# Handle authorization request
get '/authorize' do
  # Initial sanity checks and request object resolution
  session[:redirect_uri_verified] = nil # Use this for redirection in error cases
  client = OAuthHelper.identify_client params, authenticate: false
  # Used for error messages, might be overwritten by request objects
  session[:redirect_uri_verified] = client.verify_redirect_uri params[:redirect_uri], true if params[:redirect_uri]
  OAuthHelper.prepare_params params, client
  uri = client.verify_redirect_uri params[:redirect_uri], openid?(params[:scope].split) # For real this time
  session[:redirect_uri_verified] = uri
  session[:url_params] = params # Save parameters

  # We require specifying the scope
  raise OAuthError.new 'invalid_scope', 'No scopes specified' unless params[:scope]

  unless params[:response_type] == 'code'
    raise OAuthError.new 'unsupported_response_type', "Given: #{params[:response_type]}"
  end

  # Tasks the user has to perform
  session[:tasks] = []

  # We first define a minimum set of acceptable tasks
  # Require Login
  session[:tasks] << AuthorizationTask::LOGIN if session[:user].nil?
  # If consent is not yet given to the client, demand it
  unless (params[:scope].split - (session.dig(:consent, client.client_id) || [])).empty?
    session[:tasks] << AuthorizationTask::CONSENT
  end

  # The client may request some tasks on his own
  # Strictly speaking, this is OIDC only, but there is no harm in supporting it for plain OAuth,
  # since a client can at most require additional actions
  params[:prompt]&.split&.each do |task|
    case task
    when 'none'
      raise OAuthError, 'account_selection_required' if session[:tasks].include? AuthorizationTask::ACCOUNT_SELECT
      raise OAuthError, 'login_required'             if session[:tasks].include? AuthorizationTask::LOGIN
      raise OAuthError, 'consent_required'           if session[:tasks].include? AuthorizationTask::CONSENT
      raise OAuthError.new 'invalid_request', "Invalid 'prompt' values: #{params[:prompt]}" if params[:prompt] != 'none'
    when 'login'
      session[:tasks] << AuthorizationTask::LOGIN
    when 'consent'
      session[:tasks] << AuthorizationTask::CONSENT
    when 'select_account'
      session[:tasks] << AuthorizationTask::ACCOUNT_SELECT
    end
  end
  if params[:max_age] && session[:user] &&
     (Time.new.to_i - UserSession.get[session[:user]].auth_time) > params[:max_age]
    session[:tasks] << AuthorizationTask::LOGIN
  end

  # Redirect the user to start the authentication flow
  session[:tasks] << AuthorizationTask::ISSUE
  session[:tasks].sort!.uniq!
  next_task
rescue OAuthError => e
  handle_auth_error e
end

get '/consent' do
  if session[:user].nil?
    session[:tasks].unshift AuthorizationTask::LOGIN
    next_task
  end

  user = UserSession.get[session[:user]]
  raise OAuthError.new 'invalid_user', 'User session invalid' if user.nil?

  client = Client.find_by_id session.dig(:url_params, 'client_id')
  raise OAuthError.new 'invalid_client', 'Client unknown' if client.nil?

  scope_mapping = Config.scope_mapping_config
  session[:scopes] = client.filter_scopes(session.dig(:url_params, :scope).split)
  session[:scopes].select! do |s|
    p "Checking scope #{s}"
    if s.start_with? 'openid'
      true
    elsif s.include? ':'
      key, value = s.split(':', 2)
      user.claim?(key, value)
    else
      (scope_mapping[s] || []).any? { |claim| user.claim?(claim) }
    end
  end
  p "Granted scopes: #{session[:scopes]}"
  p "The user seems to be #{user.username}" if debug

  session[:resources] = [session.dig(:url_params, 'resource') || Config.base_config['default_audience']].flatten
  raise OAuthError.new 'invalid_target', 'Resources not granted' unless client.resources_allowed? session[:resources]

  # Seems to be in order
  return haml :authorization_page, locals: {
    user: user,
    client: client,
    host: Config.base_config['front_url'],
    scopes: session[:scopes],
    scope_description: Config.scope_description_config
  }
rescue OAuthError => e
  handle_auth_error e
end

post '/consent' do
  session[:consent] ||= {}
  session[:consent][session.dig(:url_params, :client_id)] = session[:scopes]
  next_task AuthorizationTask::CONSENT
rescue OAuthError => e
  handle_auth_error e
end

def issue_code
  url_params = session.delete(:url_params)
  cache = {}
  cache[:user] = UserSession.get[session[:user]]
  cache[:scopes] = session[:scopes]
  cache[:resources] = session[:resources]
  cache[:nonce] = url_params[:nonce]
  cache[:redirect_uri] = session[:redirect_uri_verified]
  cache[:claims] = JSON.parse session.dig(:url_params, 'claims') || '{}'
  unless url_params[:code_challenge].nil?
    unless url_params[:code_challenge_method] == 'S256'
      raise OAuthError.new 'invalid_request', 'Transform algorithm not supported'
    end

    cache[:pkce] = url_params[:code_challenge]
    cache[:pkce_method] = url_params[:code_challenge_method]
  end
  code = OAuthHelper.new_authz_code
  AuthorizationCache.get[code] = cache
  response_params = {
    code: code,
    state: url_params[:state],
    iss: Config.base_config['issuer']
  }
  auth_response session.delete(:redirect_uri_verified), url_params[:response_mode], response_params
end

def auth_response(redirect_uri, response_mode, response_params)
  case response_mode
  when 'form_post'
    halt 200, (haml :submitted, locals: response_params.merge({ redirect_uri: redirect_uri }))
  when 'fragment'
    redirect to("#{redirect_uri}##{URI.encode_www_form response_params}")
  else # 'query' and unsupported types
    redirect to("#{redirect_uri}?#{URI.encode_www_form response_params}")
  end
end

########## USERINFO ##################

before '/userinfo' do
  return if request.env['REQUEST_METHOD'] == 'OPTIONS'

  jwt = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
  @token = Token.decode jwt, '/userinfo'
  @client = Client.find_by_id @token['client_id']
  @user = User.find_by_id(@token['sub'])
  halt 401 if @user.nil?
rescue StandardError => e
  p e if debug
  halt 401
end

get '/userinfo' do
  headers['Content-Type'] = 'application/json'
  JSON.generate OAuthHelper.userinfo(@client, @user, @token)
end

########## LOGIN/LOGOUT ##################

get '/logout' do
  session[:user] = nil
  redirect_uri = params['post_logout_redirect_uri'] || "#{Config.base_config['front_url']}/login"
  redirect to(redirect_uri)
end

post '/logout' do
  session[:user] = nil
  redirect_uri = params['post_logout_redirect_uri'] || "#{Config.base_config['front_url']}/login"
  redirect to(redirect_uri)
end

# FIXME
# This should use a more generic way to select the OP to use
get '/login' do
  config = Config.oauth_provider_config
  providers = []
  unless config == false
    config&.each do |provider|
      url = URI(provider['authorization_endpoint'])
      params = { client_id: provider['client_id'], scope: provider['scopes'],
                 redirect_uri: provider['redirect_uri'], response_type: provider['response_type'] }
      url.query = URI.encode_www_form(params)
      providers.push({ url: url.to_s, name: provider['name'], logo: provider['logo'] })
    end
  end
  no_password_login = Config.base_config['no_password_login'] || false
  return haml :login, locals: {
    no_password_login: no_password_login,
    host: Config.base_config['front_url'],
    providers: providers
  }
end

post '/login' do
  user = User.find_by_id(params[:username])
  unless user&.verify_password(params[:password])
    redirect to("#{Config.base_config['front_url']}/login?error=\"Credentials incorrect\"")
  end
  nonce = rand(2**512)
  user.auth_time = Time.new.to_i
  UserSession.get[nonce] = user
  session[:user] = nonce
  next_task AuthorizationTask::LOGIN
rescue OAuthError => e
  handle_auth_error e
end

# FIXME
# This should also be more generic and use the correct OP
get '/oauth_cb' do
  code = params[:code]
  at = nil
  oauth_providers = Config.oauth_provider_config
  provider = oauth_providers.select { |pv| pv['name'] == params[:provider] }.first

  uri = URI(provider['token_endpoint'])
  Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
    req = Net::HTTP::Post.new(uri)
    req.set_form_data('code' => code,
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

  nonce = rand(2**512)
  user.auth_time = Time.new.to_i
  UserSession.get[nonce] = user
  session[:user] = nonce
  next_task AuthorizationTask::LOGIN
end

########## WELL-KNOWN ENDPOINTS ##################

before '/.well-known*' do
  headers['Content-Type'] = 'application/json'
  headers['Cache-Control'] = "public, max-age=#{60 * 60 * 24}, must-revalidate"
  headers.delete('Pragma')
end

get '/.well-known/jwks.json' do
  Keys.generate_jwks.to_json
end

get '/.well-known/(oauth-authorization-server|openid-configuration)' do
  OAuthHelper.configuration_metadata(Config.base_config['issuer'], Config.base_config['front_url']).to_json
end

get '/.well-known/webfinger' do
  halt 400 if params[:resource].nil?

  res = CGI.unescape(params[:resource].gsub('%20', '+'))
  halt 400 unless res.start_with? 'acct:'

  email = res[5..-1]
  Config.webfinger_config.each do |wfhost, _|
    next unless email.end_with? "@#{wfhost}"

    return JSON.generate(
      {
        subject: "acct:#{email}",
        properties: {},
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: Config.base_config['issuer']
          }
        ]
      }
    )
  end
  halt 404
end

get '/about' do
  headers['Content-Type'] = 'application/json'
  return JSON.generate({ 'version' => version,
                         'license' => OMEJDN_LICENSE })
end

# Load all Plugins
PluginLoader.initialize
