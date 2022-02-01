# frozen_string_literal: true
require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative 'config_testsetup'
require_relative '../omejdn'
require_relative '../lib/token_helper'

class AdminApiTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    TestSetup.setup
    
    client = Client.find_by_id 'testClient'
    @token = TokenHelper.build_access_token client, nil, ['omejdn:admin'], {}, TestSetup.config['host']+"/api"
    @insufficient_token = TokenHelper.build_access_token client, nil, ['omejdn:write'], {}, "test"
    @testCertificate = File.read './tests/test_resources/testClient.pem'
  end

  def teardown
    TestSetup.teardown
  end

  def test_require_admin_scope
    get '/api/v1/config/users', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@insufficient_token}" }
    # p last_response
    assert last_response.forbidden?
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
    get '/api/v1/config/clients/testClient', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal TestSetup.clients[0], JSON.parse(last_response.body)
  end

  def test_put_client
    client = TestSetup.clients[1]
    client.delete("client_id")
    client['name'] = "Alternative Name"
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
      'certificate' => @testCertificate
    }
    post '/api/v1/config/clients/testClient2/keys', cert.to_json,
         { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?
    get '/api/v1/config/clients/testClient2/keys', {},
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal cert, JSON.parse(last_response.body)
    put '/api/v1/config/clients/testClient2/keys', cert.to_json,
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/clients/testClient2/keys', {},
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal cert, JSON.parse(last_response.body)
    delete '/api/v1/config/clients/testClient2/keys', {},
           { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/clients/testClient2/keys', {},
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.not_found?
  end
end
