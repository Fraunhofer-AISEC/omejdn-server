# frozen_string_literal: true

# Enforce logging output
$stdout.sync = true
$stderr.sync = true

require 'rubygems'
require 'bundler/setup'
require 'rack'
require 'cgi'

require_relative './lib/client'
require_relative './lib/config'
require_relative './lib/user'
require_relative './lib/token_helper'
require_relative './lib/oauth_helper'
require_relative './lib/user_db'
require 'sinatra'
require 'sinatra/cookies'
# require 'sinatra/cors'
require 'sinatra/activerecord'
require 'securerandom'
require 'json/jwt'
require 'webrick'
require 'webrick/https'
require 'net/http'
require 'bcrypt'

OMEJDN_LICENSE = 'Apache2.0'

def version
  return File.read('.version').chomp if File.file? '.version'

  'unknown'
end

def debug
  Config.base_config['app_env'] != 'production'
end

def my_path
  Config.base_config['host'] + Config.base_config['path_prefix']
end

def openid?(scopes)
  Config.base_config['openid'] && (scopes.include? 'openid')
end

def adjust_config
  # account for environment overrides
  base_config = Config.base_config
  base_config['host'] = ENV['HOST'] || base_config['host']
  base_config['path_prefix'] = ENV['OMEJDN_PATH_PREFIX'] || base_config['path_prefix'] || ''
  base_config['bind_to'] = ENV['BIND_TO'] || base_config['bind_to'] || '0.0.0.0'
  base_config['allow_origin'] = ENV['ALLOW_ORIGIN'] || base_config['allow_origin'] || '*'
  base_config['app_env'] = ENV['APP_ENV'] || base_config['app_env'] || 'debug'
  base_config['accept_audience'] =
    ENV['OMEJDN_JWT_AUD_OVERRIDE'] || base_config['accept_audience'] || base_config['host']
  Config.base_config = base_config
end

def create_admin
  # Initialize admin user if given in ENV
  return unless ENV['OMEJDN_ADMIN']

  admin_name, admin_pw = ENV['OMEJDN_ADMIN'].split(':')
  p "Setting admin username `#{admin_name}' and password `#{admin_pw}'" if debug
  admin = User.find_by_id(admin_name)
  if admin.nil?
    admin = User.new
    admin.username = admin_name
    admin.attributes = [{ 'key' => 'omejdn', 'value' => 'admin' },
                        { 'key' => 'name', 'value' => 'Admin' }]
    admin.password = BCrypt::Password.create(admin_pw)
    User.add_user(admin, Config.base_config['user_backend_default'])
  else
    admin.password = BCrypt::Password.create(admin_pw)
    User.update_user(admin)
  end
end
adjust_config unless ENV['OMEJDN_IGNORE_ENV'] # We need this to not overwrite the config during tests
create_admin  unless ENV['OMEJDN_IGNORE_ENV']

configure do
  # Easier debugging for local tests
  set :raise_errors, debug && !ENV['HOST']
  set :show_exceptions, debug && ENV['HOST']
end

set :bind, Config.base_config['bind_to']
enable :sessions
set :sessions, secure: (Config.base_config['host'].start_with? 'https://')
set :session_store, Rack::Session::Pool

set :allow_origin, Config.base_config['allow_origin']
set :allow_methods, 'GET,HEAD,POST,PUT,DELETE'
set :allow_headers, 'content-type,if-modified-since, authorization'
set :expose_headers, 'location,link'
set :allow_credentials, true

# A User session dummy class. We probably want to use
# a KV-store at some point
class UserSession
  @user_session = {}
  def self.get
    @user_session
  end
end

# The format of this cache data structure is:
#
# {
#   <authorization code> => {
#                             :user => User,
#                             :nonce => <oauth nonce> (optional)
#                             :scopes => Requested scopes
#                             :resources => Requested resources
#                             :claims => claim parameter
#                             :pkce => Code challenge
#                             :pkce_method => Code challenge method
#                           },
#   <authorization code #1> => {...},
#   ...
# }
# A User session dummy class. We probably want to use
# a KV-store at some point
class RequestCache
  @request_cache = {}
  def self.get
    @request_cache
  end
end

# A cache for Pushed Authorization Requests
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
    resources = [Config.base_config.dig('token', 'audience')] if resources.empty?
    req_claims = JSON.parse(params[:claims] || '{}')
    raise OAuthError, 'invalid_target' unless client.resources_allowed? resources
  when 'authorization_code'
    cache = RequestCache.get[params[:code]]
    raise OAuthError, 'invalid_code' if cache.nil?

    OAuthHelper.validate_pkce(cache[:pkce], params[:code_verifier], cache[:pkce_method]) unless cache[:pkce].nil?
    client = OAuthHelper.identify_client params, authenticate: false
    scopes = client.filter_scopes(params[:scope]&.split)
    scopes = cache[:scopes] || [] if scopes.empty?
    resources = cache[:resources] if resources.empty?
    req_claims = cache[:claims] || {}
    req_claims = JSON.parse params[:claims] if params[:claims]
    raise OAuthError, 'invalid_scope'  unless (scopes - cache[:scopes]).empty?
    raise OAuthError, 'invalid_target' unless (resources - cache[:resources]).empty?
    raise OAuthError, 'invalid_request' if cache[:redirect_uri] && cache[:redirect_uri] != params[:redirect_uri]
  else
    raise OAuthError.new 'unsupported_grant_type', "Given: #{params[:grant_type]}"
  end
  raise OAuthError, 'access_denied' if scopes.empty?

  resources << ("#{Config.base_config['host']}/userinfo") if openid?(scopes)
  resources << ("#{Config.base_config['host']}/api") unless scopes.select { |s| s.start_with? 'omejdn:' }.empty?

  OAuthHelper.adapt_requested_claims req_claims

  user = cache&.dig(:user)
  nonce = cache&.dig(:nonce)
  id_token = TokenHelper.build_id_token client, user, scopes, req_claims, nonce if openid?(scopes)
  # RFC 9068
  access_token = TokenHelper.build_access_token client, user, scopes, req_claims, resources
  # Delete the authorization code as it is single use
  RequestCache.get.delete(params[:code])
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
    redirect to("#{my_path}/login")
  when AuthorizationTask::CONSENT
    redirect to("#{my_path}/consent")
  when AuthorizationTask::ISSUE
    # Only issue code once
    session[:tasks].delete(task)
    issue_code
  end
  # The user has jumped into some stage without an initial /authorize call
  # For now, redirect to /login
  p "Undefined task: #{task}. Redirecting to /login"
  redirect to("#{my_path}/login")
end

def handle_auth_error(error)
  # Try to determine the response_url to send the error to.
  response_url = session[:redirect_uri_verified]
  halt 400, error.to_s if response_url.nil?
  query = []
  query << "state=#{session.dig(:url_params, :state)}" unless session.dig(:url_params, :state).nil?
  query << "error=#{error.type}"
  query << "error_description=#{error.description}"
  redirect to "#{response_url}?#{query.join '&'}"
end

# Pushed Authorization Requests
post '/par' do
  raise OAuthError, 'invalid_request' if params.key(:request_uri) # Not allowed here

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
  raise OAuthError, 'invalid_scope' unless params[:scope]

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
  raise OAuthError, 'invalid_user' if user.nil?

  client = Client.find_by_id session.dig(:url_params, 'client_id')
  raise OAuthError, 'invalid_client' if client.nil?

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

  session[:resources] = [session.dig(:url_params, 'resource') || Config.base_config.dig('token', 'audience')].flatten
  raise OAuthError, 'invalid_target' unless client.resources_allowed? session[:resources]

  # Seems to be in order
  return haml :authorization_page, locals: {
    user: user,
    client: client,
    host: my_path,
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
  RequestCache.get[code] = cache
  redirect_uri = session.delete(:redirect_uri_verified)
  response_params = {
    code: code,
    state: url_params[:state]
  }
  case url_params[:response_mode]
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
  @user = nil
  return if request.env['REQUEST_METHOD'] == 'OPTIONS'

  jwt = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
  halt 401 if jwt.nil? || jwt.empty?
  begin
    key = Server.load_skey['sk']
    @token = (JWT.decode jwt, key.public_key, true, { algorithm: Config.base_config.dig('token', 'algorithm') })[0]
    @client = Client.find_by_id @token['client_id']
    @user = User.find_by_id(@token['sub'])
    halt 403 unless [*@token['aud']].include?("#{Config.base_config['host']}/userinfo")
  rescue StandardError => e
    p e if debug
    @user = nil
  end
  halt 401 if @user.nil?
end

get '/userinfo' do
  headers['Content-Type'] = 'application/json'
  JSON.generate OAuthHelper.userinfo(@client, @user, @token)
end

########## LOGIN/LOGOUT ##################

get '/logout' do
  session[:user] = nil
  redirect_uri = params['post_logout_redirect_uri'] || "#{my_path}/login"
  redirect to(redirect_uri)
end

post '/logout' do
  session[:user] = nil
  redirect_uri = params['post_logout_redirect_uri'] || "#{my_path}/login"
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
    host: my_path,
    providers: providers
  }
end

post '/login' do
  user = User.find_by_id(params[:username])
  redirect to("#{my_path}/login?error=\"Not a valid user.\"") if user.nil?
  redirect to("#{my_path}/login?error=\"Credentials incorrect\"") unless User.verify_credential(user,
                                                                                                params[:password])
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

########## User Selfservice ##########

after '/api/v1/*' do
  headers['Content-Type'] = 'application/json'
end

before '/api/v1/*' do
  return if request.env['REQUEST_METHOD'] == 'OPTIONS'

  begin
    jwt = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
    halt 401 if jwt.nil? || jwt.empty?
    token = JWT.decode(jwt, Server.load_skey['sk'].public_key, true,
                       { algorithm: Config.base_config.dig('token', 'algorithm') })[0]
    halt 403 unless [*token['aud']].include?("#{Config.base_config['host']}/api")
    @scopes = token['scope'].split
    @user_is_admin  = (@scopes.include? 'omejdn:admin')
    @user_may_write = (@scopes.include? 'omejdn:write') || @user_is_admin
    @user_may_read  = (@scopes.include? 'omejdn:read')  || @user_may_write
    @user = User.find_by_id token['sub']
    @client = Client.find_by_id token['client_id']
  rescue StandardError => e
    p e if debug
    halt 401
  end
end

before '/api/v1/user*' do
  @selfservice_config = Config.base_config['user_selfservice']
  halt 403 unless !@selfservice_config.nil? && @selfservice_config['enabled']
  halt 403 unless request.env['REQUEST_METHOD'] == 'GET' ? @user_may_read : @user_may_write
  halt 401 if @user.nil?
end

get '/api/v1/user' do
  halt 200, { 'username' => @user.username, 'attributes' => @user.attributes }.to_json
end

put '/api/v1/user' do
  editable = @selfservice_config['editable_attributes'] || []
  updated_user = User.new
  updated_user.username = @user.username
  updated_user.attributes = []
  JSON.parse(request.body.read)['attributes'].each do |e|
    updated_user.attributes << e if editable.include? e['key']
  end
  User.update_user updated_user
  halt 204
end

delete '/api/v1/user' do
  halt 403 unless @selfservice_config['allow_deletion']
  User.delete_user(@user.username)
  halt 204
end

put '/api/v1/user/password' do
  halt 403 unless @selfservice_config['allow_password_change']
  json = (JSON.parse request.body.read)
  current_password = json['currentPassword']
  new_password = json['newPassword']
  unless User.verify_credential(@user, current_password)
    halt 403, { 'passwordChange' => 'not successfull, password incorrect' }
  end
  User.change_password(@user, new_password)
  halt 204
end

get '/api/v1/user/provider' do
  # TODO: We probably do not want to send out the entire provider including secrets
  # to any user with API access
  halt 404 if @user.extern.nil?
  providers = Config.oauth_provider_config
  providers.each do |provider|
    next unless provider['name'] == @user.extern

    return JSON.generate provider
  end
  halt 404
end

########## ADMIN API ##################

before '/api/v1/config/*' do
  halt 403 unless @user_is_admin
  halt 401 if @client.nil? && @user.nil?
end

# Users
get '/api/v1/config/users' do
  halt 200, JSON.generate(User.all_users)
end

post '/api/v1/config/users' do
  json = JSON.parse request.body.read
  user = User.from_json(json)
  User.add_user(user, json['userBackend'] || Config.base_config['user_backend_default'])
  halt 201
end

get '/api/v1/config/users/:username' do
  user = User.find_by_id params['username']
  halt 404 if user.nil?
  halt 200, { 'username' => user.username, 'password' => user.password, 'attributes' => user.attributes }.to_json
end

put '/api/v1/config/users/:username' do
  user = User.find_by_id params['username']
  halt 404 if user.nil?
  updated_user = User.from_json(JSON.parse(request.body.read))
  updated_user.username = user.username
  oauth_providers = Config.oauth_provider_config
  User.update_user(updated_user, oauth_providers)
  halt 204
end

delete '/api/v1/config/users/:username' do
  user_found = User.delete_user(params['username'])
  halt 404 unless user_found
  halt 204
end

put '/api/v1/config/users/:username/password' do
  user = User.find_by_id params['username']
  halt 404 if user.nil?
  json = (JSON.parse request.body.read)
  User.change_password(user, json['newPassword'])
  halt 204
end

# Clients
get '/api/v1/config/clients' do
  JSON.generate Config.client_config
end

put '/api/v1/config/clients' do
  clients = []
  JSON.parse(request.body.read).each do |c|
    client = Client.new
    client.client_id = c['client_id']
    client.name = c['name']
    client.attributes = c['attributes']
    client.allowed_scopes = c['allowed_scopes']
    client.redirect_uri = c['redirect_uri']
    client.allowed_resources = c['allowed_resources']
    clients << client
  end
  Config.client_config = clients
  halt 204
end

post '/api/v1/config/clients' do
  client = Client.from_json(JSON.parse(request.body.read))
  clients = Client.load_clients
  clients << client
  Config.client_config = clients
  halt 201
end

get '/api/v1/config/clients/:client_id' do
  client = Client.find_by_id params['client_id']
  halt 404 if client.nil?
  halt 200, client.to_dict.to_json
end

put '/api/v1/config/clients/:client_id' do
  json = JSON.parse(request.body.read)
  clients = Client.load_clients
  clients.each do |stored_client|
    next if stored_client.client_id != params['client_id']

    stored_client.name = json['name'] unless json['name'].nil?
    stored_client.attributes = json['attributes'] unless json['attributes'].nil?
    stored_client.allowed_scopes = json['allowed_scopes'] unless json['allowed_scopes'].nil?
    stored_client.redirect_uri = json['redirect_uri'] unless json['redirect_uri'].nil?
    Config.client_config = clients
    halt 204
  end
  halt 404
end

delete '/api/v1/config/clients/:client_id' do
  clients = Client.load_clients
  clients.each do |stored_client|
    next unless stored_client.client_id.eql?(params['client_id'])

    clients.delete(stored_client)
    Config.client_config = clients
    halt 204
  end
  halt 404
end

# Client Keys
get '/api/v1/config/clients/:client_id/keys' do
  client = Client.find_by_id params['client_id']
  halt 404 if client.nil?
  certificate = client.certificate
  halt 404 if certificate.nil?
  halt 200, JSON.generate({ 'certificate' => client.certificate.to_s })
end

put '/api/v1/config/clients/:client_id/keys' do
  client = Client.find_by_id params['client_id']
  halt 404 if client.nil?
  client.certificate = JSON.parse(request.body.read)['certificate']
  halt 204
end

post '/api/v1/config/clients/:client_id/keys' do
  client = Client.find_by_id params['client_id']
  halt 404 if client.nil?
  client.certificate = JSON.parse(request.body.read)['certificate']
  halt 201
end

delete '/api/v1/config/clients/:client_id/keys' do
  client = Client.find_by_id params['client_id']
  halt 404 if client.nil?
  client.certificate = nil
  halt 204
end

# Config files
get '/api/v1/config/omejdn' do
  halt 200, JSON.generate(Config.base_config)
end

put '/api/v1/config/omejdn' do
  Config.base_config = JSON.parse request.body.read
  halt 204
end

get '/api/v1/config/user_backend' do
  halt 200, JSON.generate(Config.user_backend_config)
end

put '/api/v1/config/user_backend' do
  Config.user_backend_config = JSON.parse request.body.read
  halt 204
end

get '/api/v1/config/webfinger' do
  halt 200, JSON.generate(Config.webfinger_config)
end

put '/api/v1/config/webfinger' do
  Config.webfinger_config = JSON.parse request.body.read
  halt 204
end

get '/api/v1/config/oauth_providers' do
  halt 200, JSON.generate(Config.oauth_provider_config)
end

put '/api/v1/config/oauth_providers' do
  Config.oauth_provider_config = JSON.parse request.body.read
  halt 204
end

get '/api/v1/config/oauth_providers/:provider' do
  providers = Config.oauth_provider_config
  providers.each do |provider|
    next unless provider['name'] == params['provider']

    return JSON.generate provider
  end
  halt 404
end

post '/api/v1/config/oauth_providers/:provider' do
  new_provider = JSON.parse request.body.read
  providers = Config.oauth_provider_config
  providers.push(new_provider)
  Config.oauth_provider_config = providers
  halt 201
end

put '/api/v1/config/oauth_providers/:provider' do
  updated_provider = JSON.parse request.body.read
  providers = Config.oauth_provider_config
  providers.each do |provider|
    next unless provider['name'] == updated_provider['name']

    providers[providers.index(provider)] = updated_provider
    Config.oauth_provider_config = providers
    halt 200
  end
  halt 404
end

delete '/api/v1/config/oauth_providers/:provider' do
  providers = Config.oauth_provider_config
  providers.each do |provider|
    next unless provider['name'] == params['provider']

    providers.delete(provider)
    Config.oauth_provider_config = providers
    halt 200
  end
  halt 404
end

########## WELL-KNOWN ENDPOINTS ##################

before '/.well-known*' do
  headers['Content-Type'] = 'application/json'
  headers['Cache-Control'] = "max-age=#{60 * 60 * 24}, must-revalidate"
  headers.delete('Pragma')
end

get '/.well-known/jwks.json' do
  OAuthHelper.generate_jwks.to_json
end

get '/.well-known/(oauth-authorization-server|openid-configuration)' do
  JSON.generate OAuthHelper.configuration_metadata(Config.base_config['host'], my_path)
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
            href: my_path
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
