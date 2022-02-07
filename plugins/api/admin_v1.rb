# frozen_string_literal: true

require_relative '../../lib/config'
require_relative '../../lib/keys'
require_relative '../../lib/user'
require_relative '../../lib/client'

after '/api/v1/config/*' do
  headers['Content-Type'] = 'application/json'
end

before '/api/v1/config/*' do
  return if request.env['REQUEST_METHOD'] == 'OPTIONS'

  jwt = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
  token = Token.decode jwt, '/api'
  halt 403 unless token['scope'].split.include? 'omejdn:admin'
  halt 401 unless Client.find_by_id token['client_id']
rescue StandardError => e
  p e if debug
  halt 401
end

# Users
get '/api/v1/config/users' do
  halt 200, JSON.generate(User.all_users.map(&:to_dict))
end

post '/api/v1/config/users' do
  json = JSON.parse request.body.read
  user = User.from_dict(json)
  User.add_user(user, json['userBackend'] || Config.base_config['user_backend_default'])
  halt 201
end

get '/api/v1/config/users/:username' do
  user = User.find_by_id params['username']
  halt 404 if user.nil?
  halt 200, user.to_dict.to_json
end

put '/api/v1/config/users/:username' do
  user = User.find_by_id params['username']
  halt 404 if user.nil?
  updated_user = User.from_dict(JSON.parse(request.body.read))
  updated_user.username = user.username
  updated_user.save
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
  user.update_password(json['newPassword'])
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
  client = Client.from_dict(JSON.parse(request.body.read))
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
  halt 200, JSON.generate(Config.base_config.dig('plugins', 'user_db') || {})
end

put '/api/v1/config/user_backend' do
  config = Config.base_config
  config['plugins'] ||= {}
  config['plugins']['user_db'] = JSON.parse request.body.read
  Config.base_config = config
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
