# frozen_string_literal: true

ENV['APP_ENV'] = 'test'

require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative '../omejdn'
require_relative '../lib/token_helper'

class AdminApiTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    client = Client.find_by_id 'testClient'
    @token = TokenHelper.build_access_token client, ['omejdn:admin'], nil
    @insufficient_token = TokenHelper.build_access_token client, ['omejdn:write'], nil
    @testCertificate = File.read './tests/keys/testClient.pem'
  end

  def teardown
    File.open('./config/users.yml', 'w') { |file| file.write(users.to_yaml) }
    File.open('./config/clients.yml', 'w') { |file| file.write(clients.to_yaml) }
    File.open('./config/omejdn.yml', 'w') { |file| file.write(config.to_yaml) }
  end

  def users
    [{
      'username' => 'testUser',
      'attributes' => [
        { 'key' => 'omejdn', 'value' => 'write' },
        { 'key' => 'openid', 'value' => true },
        { 'key' => 'profile', 'value' => true },
        { 'key' => 'email', 'value' => 'admin@example.com' },
        { 'key' => 'asdfasf', 'value' => 'asdfasf' },
        { 'key' => 'exampleKey', 'value' => 'exampleValue' }
      ],
      'password' => "$2a$12$Be9.8qVsGOVpUFO4ebiMBel/TNetkPhnUkJ8KENHjHLiDG.IXi0Zi"
    }]
  end

  def clients
    [{
      'client_id' => 'testClient',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => []
    },
    {
      'client_id' => 'testClient2',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => []
    }]
  end

  def config
    {
      'host' => 'http://localhost:4567',
      'openid' => true,
      'token' => {
        'expiration' => 3600,
        'signing_key' => 'omejdn_priv.pem',
        'algorithm' => 'RS256',
        'audience' => 'TestServer',
        'issuer' => 'http://localhost:4567'
      },
      'id_token' => {
        'expiration' => 3600,
        'signing_key' => 'omejdn_priv.pem',
        'algorithm' => 'RS256',
        'issuer' => 'http://localhost:4567'
      },
      'user_backend' => [ 'yaml' ]
    }
  end

  def test_require_admin_scope
    get '/api/v1/config/users', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@insufficient_token}" }
    #p last_response
    assert last_response.forbidden?
  end

  def test_get_users
    get '/api/v1/config/users', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    #p last_response
    assert last_response.ok?
    assert_equal users, JSON.parse(last_response.body)
  end

  def test_get_user
    get '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    #p last_response
    assert last_response.ok?
    assert_equal users[0], JSON.parse(last_response.body)
  end

  def test_post_user
    user = {
      'username' => 'testUser2',
      'attributes' => [
        { 'key' => 'exampleKey2', 'value' => 'exampleValue2' }
      ],
      'password' => "somepw",
    }
    post '/api/v1/config/users', user.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    #p last_response
    assert last_response.created?
    get '/api/v1/config/users/testUser2', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    #p last_response
    assert last_response.ok?
    new_user = JSON.parse(last_response.body)
    assert_equal BCrypt::Password.new(new_user['password']), user['password']
    new_user.delete('password') # This will be a salted string
    user.delete('password')
    assert_equal user, new_user
  end

  def test_put_user
    user = {
      'username' => 'testUser',
      'attributes' => [
        { 'key' => 'exampleKey', 'value' => 'exampleValue2' }
      ],
      'password' => "secure",
    }
    put '/api/v1/config/users/testUser', user.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    new_user = JSON.parse(last_response.body)
    assert_equal BCrypt::Password.new(new_user['password']), user['password']
    user.delete('password')
    new_user.delete('password')
    assert_equal user, new_user
  end

  def test_delete_user
    delete '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    #p last_response
    assert last_response.no_content?
    get '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.not_found?
    assert_equal '', last_response.body
  end

  def test_change_user_password
    payload = {
      'newPassword' => "extremelysecure",
    }
    put '/api/v1/config/users/testUser/password', payload.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    user = JSON.parse(last_response.body)
    assert_equal BCrypt::Password.new(user['password']), payload['newPassword']
  end

  def test_get_clients
    get '/api/v1/config/clients', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal clients, JSON.parse(last_response.body)
  end

  def test_put_clients
    new_clients = clients
    new_clients[1]['name']="Test name"
    put '/api/v1/config/clients', new_clients.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/clients', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal new_clients, JSON.parse(last_response.body)
  end

  def test_get_client
    get '/api/v1/config/clients/testClient', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal clients[0], JSON.parse(last_response.body)
  end

  def test_put_client
    client = {
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => []
    }
    put '/api/v1/config/clients/testClient2', client.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/clients/testClient2', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    client['client_id'] = 'testClient2'
    assert_equal client, JSON.parse(last_response.body)
  end

  def test_post_client
    client = {
      'client_id' => 'testClient3',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => []
    }
    post '/api/v1/config/clients', client.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?
    get '/api/v1/config/clients/testClient3', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal client, JSON.parse(last_response.body)
  end

  def test_delete_client
    delete '/api/v1/config/clients/testClient2', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/clients/testClient2', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.not_found?
    assert_equal '', last_response.body
  end

  def test_get_config
    get '/api/v1/config/omejdn', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal config, JSON.parse(last_response.body)
  end

  def test_put_config
    
    put '/api/v1/config/omejdn', config.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/omejdn', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal config, JSON.parse(last_response.body)
  end

  def test_put_certificate
    cert = {
      'certificate' => @testCertificate
    }
    put '/api/v1/config/clients/testClient/keys', cert.to_json,
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/clients/testClient/keys', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal cert, JSON.parse(last_response.body)
    cert = {
      'certificate' => "-----BEGIN CERTIFICATE-----
MIICQzCCAaygAwIBAgIBATANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAt0ZXN0
Q2xpZW50MjAeFw0yMDAzMTgxNzQzMzdaFw0yMTAzMTgxNzQzMzdaMBYxFDASBgNV
BAMMC3Rlc3RDbGllbnQyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTO7ov
BQ0FvgNIDIloz3uPKHe7XBiDerYwX+S+L1sWIUXvcKpY/igs0gqmNOWTknkrrVKW
l62iPGOhrTsig+jOkHX5mmj8P0Y+bf0zMIWceX4S0d6O2ZC1lv08Be/CX/jGSUmU
FRWSvGo+TKPQqWn/4Bf28DduVw2p6z917H30LwIDAQABo4GgMIGdMAkGA1UdEwQC
MAAwCwYDVR0PBAQDAgUgMB0GA1UdDgQWBBRk8oaobfGpvv6kOd3Yw31YHV2jrDAT
BgNVHSUEDDAKBggrBgEFBQcDATAPBglghkgBhvhCAQ0EAhYAMD4GA1UdIwQ3MDWA
FGTyhqht8am+/qQ53djDfVgdXaOsoRqkGDAWMRQwEgYDVQQDDAt0ZXN0Q2xpZW50
MoIBATANBgkqhkiG9w0BAQsFAAOBgQCo2oYpH/MzunB4eP7Mwek9UrRcXp10rL4D
PExqY4rJ43CWpPOjIWAxCLRic/x3P0K19ukZk9GHNdQerUvyAJiubo8iH366kXfu
9+XBMDtJ5tvhwn0nTylTTaWnSu47O/o9DWfzlGoYfLV1jTrvwUcozymVWprnmeCs
3WF1B0RcEQ==
-----END CERTIFICATE-----"
    }
    put '/api/v1/config/clients/keys/testClient', cert.to_json,
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
  end

  def test_post_certificate
    cert = {
      'certificate' => @testCertificate
    }
    post '/api/v1/config/clients/testClient2/keys', cert.to_json,
         { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?
    get '/api/v1/config/clients/testClient2/keys', {},
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal cert, JSON.parse(last_response.body)
  end

  def test_delete_certificate
    delete '/api/v1/config/clients/testClient2/keys', {},
         { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/clients/testClient2/keys', {},
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.not_found?
  end
end