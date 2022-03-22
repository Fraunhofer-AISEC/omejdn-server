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
endpoint '/api/v1/config/users', ['GET'], public_endpoint: true do
  halt 200, JSON.generate(User.all_users.map(&:to_dict))
end

endpoint '/api/v1/config/users', ['POST'], public_endpoint: true do
  json = JSON.parse request.body.read
  user = User.from_dict(json)
  User.add_user(user, json['userBackend'] || Config.base_config['user_backend_default'])
  halt 201
end

endpoint '/api/v1/config/users/:username', ['GET'], public_endpoint: true do
  user = User.find_by_id params['username']
  halt 404 if user.nil?
  halt 200, user.to_dict.to_json
end

endpoint '/api/v1/config/users/:username', ['PUT'], public_endpoint: true do
  user = User.find_by_id params['username']
  halt 404 if user.nil?
  updated_user = User.from_dict(JSON.parse(request.body.read))
  updated_user.username = user.username
  updated_user.save
  halt 204
end

endpoint '/api/v1/config/users/:username', ['DELETE'], public_endpoint: true do
  user_found = User.delete_user(params['username'])
  halt 404 unless user_found
  halt 204
end

endpoint '/api/v1/config/users/:username/password', ['PUT'], public_endpoint: true do
  user = User.find_by_id params['username']
  halt 404 if user.nil?
  json = (JSON.parse request.body.read)
  user.update_password(json['newPassword'])
  halt 204
end

# Clients
endpoint '/api/v1/config/clients', ['GET'], public_endpoint: true do
  JSON.generate Config.client_config
end

endpoint '/api/v1/config/clients', ['PUT'], public_endpoint: true do
  Config.client_config = JSON.parse(request.body.read).map do |c|
    client = Client.new
    client.apply_values(c)
    client
  end
  halt 204
end

endpoint '/api/v1/config/clients', ['POST'], public_endpoint: true do
  client = Client.from_dict(JSON.parse(request.body.read))
  clients = Client.load_clients
  clients << client
  Config.client_config = clients
  halt 201
end

endpoint '/api/v1/config/clients/:client_id', ['GET'], public_endpoint: true do
  client = Client.find_by_id params['client_id']
  halt 404 if client.nil?
  halt 200, client.to_dict.to_json
end

endpoint '/api/v1/config/clients/:client_id', ['PUT'], public_endpoint: true do
  json = JSON.parse(request.body.read)
  clients = Client.load_clients
  clients.each do |stored_client|
    next if stored_client.client_id != params['client_id']

    stored_client.attributes = json.delete('attributes') unless json['attributes'].nil?
    stored_client.metadata.merge!(json)
    Config.client_config = clients
    halt 204
  end
  halt 404
end

endpoint '/api/v1/config/clients/:client_id', ['DELETE'], public_endpoint: true do
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
endpoint '/api/v1/config/clients/:client_id/keys', ['GET'], public_endpoint: true do
  client = Client.find_by_id params['client_id']
  halt 404 if client.nil?
  certificate = client.certificate
  halt 404 if certificate.nil?
  halt 200, JSON.generate({ 'certificate' => client.certificate.to_s })
end

endpoint '/api/v1/config/clients/:client_id/keys', ['PUT'], public_endpoint: true do
  client = Client.find_by_id params['client_id']
  halt 404 if client.nil?
  client.certificate = JSON.parse(request.body.read)['certificate']
  halt 204
end

endpoint '/api/v1/config/clients/:client_id/keys', ['POST'], public_endpoint: true do
  client = Client.find_by_id params['client_id']
  halt 404 if client.nil?
  client.certificate = JSON.parse(request.body.read)['certificate']
  halt 201
end

endpoint '/api/v1/config/clients/:client_id/keys', ['DELETE'], public_endpoint: true do
  client = Client.find_by_id params['client_id']
  halt 404 if client.nil?
  client.certificate = nil
  halt 204
end

# Config files
endpoint '/api/v1/config/omejdn', ['GET'], public_endpoint: true do
  halt 200, JSON.generate(Config.base_config)
end

endpoint '/api/v1/config/omejdn', ['PUT'], public_endpoint: true do
  Config.base_config = JSON.parse request.body.read
  halt 204
end

endpoint '/api/v1/config/user_backend', ['GET'], public_endpoint: true do
  halt 200, JSON.generate(Config.base_config.dig('plugins', 'user_db') || {})
end

endpoint '/api/v1/config/user_backend', ['PUT'], public_endpoint: true do
  config = Config.base_config
  config['plugins'] ||= {}
  config['plugins']['user_db'] = JSON.parse request.body.read
  Config.base_config = config
  halt 204
end

endpoint '/api/v1/config/webfinger', ['GET'], public_endpoint: true do
  halt 200, JSON.generate(Config.webfinger_config)
end

endpoint '/api/v1/config/webfinger', ['PUT'], public_endpoint: true do
  Config.webfinger_config = JSON.parse request.body.read
  halt 204
end

endpoint '/api/v1/config/oauth_providers', ['GET'], public_endpoint: true do
  halt 200, JSON.generate(Config.oauth_provider_config)
end

endpoint '/api/v1/config/oauth_providers', ['PUT'], public_endpoint: true do
  Config.oauth_provider_config = JSON.parse request.body.read
  halt 204
end

endpoint '/api/v1/config/oauth_providers/:provider', ['GET'], public_endpoint: true do
  providers = Config.oauth_provider_config
  providers.each do |provider|
    next unless provider['name'] == params['provider']

    return JSON.generate provider
  end
  halt 404
end

endpoint '/api/v1/config/oauth_providers/:provider', ['POST'], public_endpoint: true do
  new_provider = JSON.parse request.body.read
  providers = Config.oauth_provider_config
  providers.push(new_provider)
  Config.oauth_provider_config = providers
  halt 201
end

endpoint '/api/v1/config/oauth_providers/:provider', ['PUT'], public_endpoint: true do
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

endpoint '/api/v1/config/oauth_providers/:provider', ['DELETE'], public_endpoint: true do
  providers = Config.oauth_provider_config
  providers.each do |provider|
    next unless provider['name'] == params['provider']

    providers.delete(provider)
    Config.oauth_provider_config = providers
    halt 200
  end
  halt 404
end
