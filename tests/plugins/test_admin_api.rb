# frozen_string_literal: true
require 'test/unit'
require 'rack/test'

ENV['OMEJDN_PLUGINS'] = 'tests/test_resources/plugins_test_admin_api.yml'
require_relative '../config_testsetup'
require_relative '../../lib/token'

class AdminApiTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    TestSetup.setup
    
    @client = Client.find_by_id 'private_key_jwt_client'
    @client2 = Client.find_by_id 'publicClient'
    @token = Token.access_token @client, nil, ['omejdn:admin'], {}, TestSetup.config['front_url']+"/api"
    @insufficient_token = Token.access_token @client, nil, ['omejdn:write'], {}, "test"
    @testCertificate = OpenSSL::X509::Certificate.new File.read('./tests/test_resources/testClient.pem')
  end

  def test_require_admin_scope
    get '/api/v1/config/users', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@insufficient_token}" }
    # p last_response
    assert last_response.unauthorized?
  end

  def test_get_users
    get '/api/v1/config/users', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    # p last_response
    assert last_response.ok?
    assert_equal TestSetup.users, JSON.parse(last_response.body)
  end

  def test_get_user
    get '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    # p last_response
    assert last_response.ok?
    assert_equal TestSetup.users[0], JSON.parse(last_response.body)
  end

  def test_post_user
    user = {
      'username' => 'testUser3',
      'attributes' => [
        { 'key' => 'exampleKey2', 'value' => 'exampleValue2' }
      ],
      'password' => 'somepw',
      'backend' => 'yaml'
    }
    post '/api/v1/config/users', user.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    # p last_response
    assert last_response.created?
    get '/api/v1/config/users/testUser3', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    # p last_response
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
      'password' => 'secure',
      'backend' => 'yaml'
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
    # p last_response
    assert last_response.no_content?
    get '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.not_found?
    assert_equal '', last_response.body
  end

  def test_change_user_password
    payload = {
      'newPassword' => 'extremelysecure'
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
    assert_equal TestSetup.clients, JSON.parse(last_response.body)
  end

  def test_put_clients
    new_clients = TestSetup.clients
    new_clients[1]['name'] = 'Test name'
    put '/api/v1/config/clients', new_clients.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/clients', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal new_clients, JSON.parse(last_response.body)
  end

  def test_get_client
    get "/api/v1/config/clients/#{@client.client_id}", {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal @client.to_h, JSON.parse(last_response.body)
  end

  def test_put_client
    client_desc = @client.to_h
    client_desc.delete("client_id")
    client_desc['name'] = "Alternative Name"
    put "/api/v1/config/clients/#{@client.client_id}", client_desc.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get "/api/v1/config/clients/#{@client.client_id}", {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    client_desc['client_id'] = @client.client_id
    assert_equal client_desc, JSON.parse(last_response.body)
  end

  def test_post_client
    new_client = {
      'client_id' => 'testClient3',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => []
    }
    post '/api/v1/config/clients', new_client.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?
    get '/api/v1/config/clients/testClient3', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal new_client, JSON.parse(last_response.body)
  end

  def test_delete_client
    delete "/api/v1/config/clients/#{@client2.client_id}", {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get "/api/v1/config/clients/#{@client2.client_id}", {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.not_found?
    assert_equal '', last_response.body
  end

  def test_get_config
    get '/api/v1/config/omejdn', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal TestSetup.config, JSON.parse(last_response.body)
  end

  def test_put_config
    put '/api/v1/config/omejdn', TestSetup.config.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/omejdn', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal TestSetup.config, JSON.parse(last_response.body)
  end

  def test_post_put_delete_certificate
    cert = {
      'certificate' => @testCertificate.to_pem
    }
    post "/api/v1/config/clients/#{@client.client_id}/keys", cert.to_json,
         { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?
    get "/api/v1/config/clients/#{@client.client_id}/keys", {},
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal cert, JSON.parse(last_response.body)
    put "/api/v1/config/clients/#{@client.client_id}/keys", cert.to_json,
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get "/api/v1/config/clients/#{@client.client_id}/keys", {},
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal cert, JSON.parse(last_response.body)
    delete "/api/v1/config/clients/#{@client.client_id}/keys", {},
           { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get "/api/v1/config/clients/#{@client.client_id}/keys", {},
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.not_found?
  end
end
