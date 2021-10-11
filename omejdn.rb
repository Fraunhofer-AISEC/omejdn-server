# frozen_string_literal: true

require 'rubygems'
require 'bundler/setup'

require_relative './lib/client'
require_relative './lib/config'
require_relative './lib/user'
require_relative './lib/token_helper'
require_relative './lib/oauth_helper'
require_relative './lib/user_db'
require 'sinatra'
require 'sinatra/cookies'
require 'sinatra/cors'
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
  ENV['APP_ENV'] != 'production'
end

def host
  ENV['HOST'] || Config.base_config['host']
end

def my_prefix
  ENV['OMEJDN_PATH_PREFIX'] || ''
end

def my_path
  host + my_prefix
end

configure do
  # Easier debugging for local tests
  set :raise_errors, debug && !ENV['HOST']
  set :show_exceptions, debug && ENV['HOST']
end

set :bind, ENV['BIND_TO'] || '0.0.0.0'
enable :sessions
set :sessions, secure: (host.start_with? 'https://')
set :session_store, Rack::Session::Pool

set :allow_origin, ENV['ALLOW_ORIGIN'] || 'http://localhost:4200'
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

# Initialize admin user if given in ENV
if ENV['OMEJDN_ADMIN']
  admin_name, admin_pw = ENV['OMEJDN_ADMIN'].split(':')
  p "Setting admin username `#{admin_name}' and password `#{admin_pw}'" if debug
  admin = User.find_by_id(admin_name)
  if admin.nil?
    admin = User.new
    admin.username = admin_name
    admin.attributes = [{ 'key' => 'omejdn', 'value' => 'admin' },
                        { 'key' => 'name', 'value' => 'Admin' }]
    admin.password = BCrypt::Password.create(admin_pw)
    User.add_user(admin, 'yaml')
  else
    admin.password = BCrypt::Password.create(admin_pw)
    User.update_user(admin)
  end
end

before do
  return if request.get_header('HTTP_ORIGIN').nil?
  unless request.get_header('HTTP_ORIGIN').start_with?('chrome-extension://') ||
         request.get_header('HTTP_ORIGIN').start_with?('moz-extension://')
    return
  end

  response.headers['Access-Control-Allow-Origin'] = request.get_header('HTTP_ORIGIN').to_s
end

# Handle token request
post '/token' do
  client = nil
  scopes = []
  if params[:grant_type] == 'client_credentials'
    if params[:client_assertion_type] != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      halt 400, OAuthHelper.error_response('invalid_request', 'Invalid client_assertion_type')
    end
    jwt = params[:client_assertion]
    halt 400, OAuthHelper.error_response('invalid_client', 'Assertion missing') if jwt.nil?
    client = Client.find_by_jwt jwt
    halt 400, OAuthHelper.error_response('invalid_client', 'Client unknown') if client.nil?
  elsif (params[:grant_type] == 'authorization_code') && Config.base_config['openid']
    code = params[:code]
    # Only verify PKCE if given in request
    unless RequestCache.get[code][:pkce].nil?
      halt 400, OAuthHelper.error_response('invalid_request', 'Code verifier missing') if params[:code_verifier].nil?
      unless OAuthHelper.validate_pkce(RequestCache.get[code][:pkce],
                                       params[:code_verifier],
                                       RequestCache.get[code][:pkce_method])
        halt 400,
             OAuthHelper.error_response('invalid_request', 'Code verifier mismatch')
      end
    end
    client = Client.find_by_id params[:client_id]
    halt 400, OAuthHelper.error_response('invalid_client', 'No client_id given') if client.nil?
    halt 400, OAuthHelper.error_response('invalid_code', '') if code.nil?
    halt 400, OAuthHelper.error_response('invalid_code', '') unless RequestCache.get.keys.include?(code)
    scopes = RequestCache.get[code][:scopes] unless RequestCache.get[code][:scopes].nil?
  else
    halt 400, OAuthHelper.error_response('unsupported_grant_type', "Given: #{params[:grant_type]}")
  end
  headers['Content-Type'] = 'application/json'
  scopes = params[:scope]&.split if scopes.empty?
  # FIXME: filter scopes! Clients that are not authorized must be notified.
  id_token_claims = {}
  if !RequestCache.get[code].nil? &&
     RequestCache.get[code][:claims].key?('id_token') &&
     !RequestCache.get[code][:claims].empty?
    id_token_claims = RequestCache.get[code][:claims]['id_token']
  end
  begin
    user = nil
    user = RequestCache.get[code][:user] unless RequestCache.get[code].nil?
    # https://tools.ietf.org/html/draft-bertocci-oauth-access-token-jwt-00#section-2.2
    access_token = TokenHelper.build_access_token client, scopes, user
    if scopes.include?('openid')
      id_token = TokenHelper.build_id_token client, user,
                                            RequestCache.get[code][:nonce],
                                            id_token_claims, scopes
    end
    # Delete the authorization code as it is single use
    RequestCache.get.delete(code)
    OAuthHelper.token_response access_token, scopes, id_token
  rescue OAuth2Error
    halt 400, OAuthHelper.error_response('invalid_scope', '')
  end
end

get '/.well-known/openid-configuration' do
  headers['Content-Type'] = 'application/json'
  p "Host #{host},#{my_path}"
  JSON.generate OAuthHelper.openid_configuration(host, my_path)
end

# Handle authorization request
get '/authorize' do
  unless Config.base_config['openid']
    status 404
    return
  end
  session[:url_params] = params
  redirect to("#{my_path}/login") if session['user'].nil?
  user = nil
  unless params[:response_type] == 'code'
    return OAuthHelper.error_response 'unsupported_response_type', "Given: #{params[:response_type]}"
  end

  user = UserSession.get[session['user']]
  return OAuthHelper.error_response 'invalid_user', '' if user.nil?

  session[:scopes] = []
  scope_mapping = Config.scope_mapping_config

  params[:scope].split.each do |s|
    p "Checking scope #{s}"
    session[:scopes].push(s) if s == 'openid'

    # "key:value" scopes
    if (s.include? ':') && user.claim?(s)
      session[:scopes].push(s)
      next
    end

    next if scope_mapping[s].nil? || (s.include? ':')

    scope_mapping[s].each do |claim|
      next unless user.claim?(claim)

      session[:scopes].push(s)
      break
    end
  end
  p "Granted scopes: #{session[:scopes]}"
  p "The user seems to be #{user.username}" if debug
  client = Client.find_by_id params['client_id']
  return OAuthHelper.error_response 'invalid_client' if client.nil?

  escaped_redir = CGI.unescape(params[:redirect_uri].gsub('%20', '+'))
  return OAuthHelper.error_response 'invalid_redirect_uri', '' unless [client.redirect_uri, 'localhost'].any? do |uri|
                                                                        escaped_redir.include? uri
                                                                      end

  # Seems to be in order
  return haml :authorization_page, locals: {
    user: user,
    client: client,
    host: my_path,
    scopes: session[:scopes],
    scope_description: Config.scope_description_config
  }
end

post '/authorize' do
  code = OAuthHelper.new_authz_code
  RequestCache.get[code] = {}
  RequestCache.get[code][:user] = UserSession.get[session['user']]
  RequestCache.get[code][:scopes] = session[:scopes]
  RequestCache.get[code][:nonce] = session[:url_params][:nonce]
  RequestCache.get[code][:claims] = {}
  RequestCache.get[code][:claims] = JSON.parse session[:url_params]['claims'] if session[:url_params].key?('claims')
  unless session[:url_params][:code_challenge].nil?
    unless session[:url_params][:code_challenge_method] == 'S256'
      return OAuthHelper.error_response 'invalid_request',
                                        'Transform algorithm not supported'
    end

    RequestCache.get[code][:pkce] = session[:url_params][:code_challenge]
    RequestCache.get[code][:pkce_method] = session[:url_params][:code_challenge_method]
  end
  redirect_uri = session[:url_params][:redirect_uri]
  resp = "?code=#{code}&state=#{session[:url_params][:state]}"
  redirect to(redirect_uri + resp)
end

get '/.well-known/jwks.json' do
  headers['Content-Type'] = 'application/json'
  OAuthHelper.generate_jwks.to_json
end

before '/userinfo' do
  @user = nil
  return if request.env['REQUEST_METHOD'] == 'OPTIONS'

  jwt = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
  halt 401 if jwt.nil? || jwt.empty?
  begin
    key = Server.load_key
    @token = JWT.decode jwt, key.public_key, true, { algorithm: 'RS256' }
    @user = User.find_by_id(@token[0]['sub'])
  rescue StandardError => e
    p e if debug
    @user = nil
  end
  halt 401 if @user.nil?
end

get '/userinfo' do
  headers['Content-Type'] = 'application/json'
  # JSON.generate OAuthHelper.access_token_to_userinfo(@token)
  JSON.generate OAuthHelper.userinfo(@user, @token)
end

########## LOGIN/LOGOUT ##################

get '/logout' do
  session['user'] = nil
  redirect to("#{my_path}/login")
end

post '/logout' do
  redirect_uri = session['post_logout_redirect_uri']
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
  no_password_login = Config.base_config['no_password_login']
  no_password_login = false if no_password_login.nil?
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
  UserSession.get[nonce] = user
  session['user'] = nonce
  if session[:url_params].nil?
    redirect to("#{my_path}/login")
  else
    redirect to("#{my_path}/authorize?#{URI.encode_www_form(session[:url_params]).gsub('+', '%20')}")
  end
end

# FIXME
# This should also be more generic and use the correct OP
get '/oauth_cb' do
  oauth_providers = Config.oauth_provider_config
  code = params[:code]
  at = nil
  provider_index = 0
  oauth_providers.each do |provider|
    break if provider['name'] == params[:provider]

    provider_index += 1
  end
  uri = URI(oauth_providers[provider_index]['token_endpoint'])
  Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
    req = Net::HTTP::Post.new(uri)
    req.set_form_data('code' => code,
                      'client_id' => oauth_providers[provider_index]['client_id'],
                      'client_secret' => oauth_providers[provider_index]['client_secret'],
                      'grant_type' => 'authorization_code',
                      'redirect_uri' => oauth_providers[provider_index]['redirect_uri'])
    res = http.request req
    at = JSON.parse(res.body)['access_token']
  end
  return 'Unauthorized' if at.nil?

  user = nil
  nonce = rand(2**512)
  uri = URI(oauth_providers[provider_index]['userinfo_endpoint'])
  Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
    req = Net::HTTP::Get.new(uri)
    req['Authorization'] = "Bearer #{at}"
    res = http.request req
    user = User.generate_extern_user(oauth_providers[provider_index], JSON.parse(res.body))
  end
  return 'Internal Error' if user.username.nil?

  UserSession.get[nonce] = user
  session['user'] = nonce
  redirect to(my_path) if session[:url_params].nil? # This is actually an error
  redirect to("#{my_path}/authorize?#{URI.encode_www_form(session[:url_params])}")
end

########## User Selfservice ##########

after '/api/v1/*' do
  headers['Content-Type'] = 'application/json'
end

before '/api/v1/user*' do
  return if request.env['REQUEST_METHOD'] == 'OPTIONS'

  jwt = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
  halt 401 if jwt.nil? || jwt.empty?
  @user_is_admin  = false
  @user_may_read  = false
  @user_may_write = false
  begin
    key = Server.load_key
    token = JWT.decode(jwt, key.public_key, true, { algorithm: 'RS256' })
    @user_is_admin  = (token[0]['scopes'].include? 'omejdn:admin')
    @user_may_write = (token[0]['scopes'].include? 'omejdn:write') || @user_is_admin
    @user_may_read  = (token[0]['scopes'].include? 'omejdn:read')  || @user_may_write
    halt 403 unless @user_may_read
    halt 403 unless @user_may_write || request.env['REQUEST_METHOD'] == 'GET'
    @user = User.find_by_id token[0]['sub']
  rescue StandardError => e
    p e if debug
    @user = nil
  end
  halt 401 if @user.nil?
end

get '/api/v1/user' do
  halt 200, { 'username' => @user.username, 'attributes' => @user.attributes }.to_json
end

put '/api/v1/user' do
  # FIXME: There are no checks as to what attributes can be altered
  # A user could simply add additional claims like omejdn:admin.
  # We should also ensure a user cannot change another user.
  # And changing a password here skips checking for the current one
  # in the endpoint below
  updated_user = User.from_json(JSON.parse(request.body.read))
  updated_user.username = @user.username
  User.update_user updated_user
  halt 204
end

delete '/api/v1/user' do
  User.delete_user(@user.username)
  halt 204
end

put '/api/v1/user/password' do
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
  return if request.env['REQUEST_METHOD'] == 'OPTIONS'

  jwt = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
  halt 401 if jwt.nil? || jwt.empty?
  begin
    key = Server.load_key
    token = JWT.decode(jwt, key.public_key, true, { algorithm: 'RS256' })
    halt 403 unless token[0]['scopes'].include? 'omejdn:admin'
    @user = User.find_by_id token[0]['sub'] if token[0]['scopes'].include? 'openid'
    @client = Client.find_by_id token[0]['sub'] unless (token[0]['scopes']).include? 'openid'
  rescue StandardError => e
    p e if debug
    @client = nil
    @user = nil
  end
  halt 401 if @client.nil? && @user.nil?
end

# Users
get '/api/v1/config/users' do
  halt 200, JSON.generate(User.all_users)
end

post '/api/v1/config/users' do
  json = JSON.parse request.body.read
  user = User.from_json(json)
  User.add_user(user, json['userBackend'] || 'yaml')
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
  halt 200, client.to_json
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

get '/.well-known/webfinger' do
  halt 400 if params[:resource].nil?

  res = CGI.unescape(params[:resource].gsub('%20', '+'))
  halt 400 unless res.start_with? 'acct:'

  email = res[5..-1]
  YAML.load_file('config/webfinger.yml').each do |wfhost, _|
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
