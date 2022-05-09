# frozen_string_literal: true

require_relative '../../lib/config'
require_relative '../../lib/keys'
require_relative '../../lib/user'

after '/api/v1/user*' do
  headers['Content-Type'] = 'application/json'
end

before '/api/v1/user*' do
  return if request.env['REQUEST_METHOD'] == 'OPTIONS'

  jwt = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
  token = Token.decode jwt, '/api'
  scopes = token['scope'].split
  user_may_write = !(scopes & ['omejdn:admin', 'omejdn:write']).empty?
  user_may_read  = !(scopes & ['omejdn:admin', 'omejdn:write', 'omejdn:read']).empty?
  halt 403 unless request.env['REQUEST_METHOD'] == 'GET' ? user_may_read : user_may_write
  @user = User.find_by_id token['sub']
  @selfservice_config = PluginLoader.configuration('user_selfservice') || {
    'editable_attributes' => [],
    'allow_deletion' => false,
    'allow_password_change' => false
  }
  halt 401 if @user.nil?
rescue StandardError => e
  p e if debug
  halt 401
end

endpoint '/api/v1/user', ['GET'], public_endpoint: true do
  halt 200, { 'username' => @user.username, 'attributes' => @user.attributes }.to_json
end

endpoint '/api/v1/user', ['PUT'], public_endpoint: true do
  editable = @selfservice_config['editable_attributes'] || []
  updated_user = User.new
  updated_user.username = @user.username
  updated_user.attributes = []
  updated_user.backend = @user.backend
  updated_user.extern = @user.extern
  JSON.parse(request.body.read)['attributes'].each do |e|
    updated_user.attributes << e if editable.include? e['key']
  end
  updated_user.save
  halt 204
end

endpoint '/api/v1/user', ['DELETE'], public_endpoint: true do
  halt 403 unless @selfservice_config['allow_deletion']
  User.delete_user(@user.username)
  halt 204
end

endpoint '/api/v1/user/password', ['PUT'], public_endpoint: true do
  halt 403 unless @selfservice_config['allow_password_change']
  json = (JSON.parse request.body.read)
  current_password = json['currentPassword']
  new_password = json['newPassword']
  unless @user.verify_password(current_password)
    halt 403,
         { 'passwordChange' => 'not successfull, password incorrect' }
  end
  @user.update_password(new_password)
  halt 204
end

endpoint '/api/v1/user/provider', ['GET'], public_endpoint: true do
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
