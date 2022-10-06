# frozen_string_literal: true
require 'test/unit'
require 'rack/test'

ENV['OMEJDN_PLUGINS'] = 'tests/test_resources/plugins_test_admin_api_v2.yml'
require_relative '../config_testsetup'
require_relative '../../lib/token'
require_relative '../../plugins/admin_api_v2/admin_api_v2'

require 'json-schema'

class AdminApiV2Test < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    TestSetup.setup
    
    @client = Client.find_by_id 'private_key_jwt_client'
    @token = Token.access_token @client, nil, ['omejdn:admin'], {}, TestDB.config.dig('omejdn','front_url')+"/api"
    @insufficient_token = Token.access_token @client, nil, ['omejdn:write'], {}, TestDB.config.dig('omejdn','front_url')+"/api"
  end

  # ---------- GENERAL/ERRORS ----------

  def test_require_authorization
    get '/api/admin/v2/config/omejdn', {}, {}
    assert last_response.unauthorized?
    get '/api/admin/v2/config/omejdn', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@insufficient_token}" }
    assert last_response.forbidden?
  end

  def test_malformed_json
    put '/api/admin/v2/config/appletree', '{I am not JSON', { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.bad_request?
  end

  # ---------- CONFIG ----------

  def test_config
    # Retrieve Main Configuration
    get '/api/admin/v2/config/omejdn', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert JSON::Validator.validate(SCHEMA_CONFIG, (response = JSON.parse(last_response.body)))
    assert_equal TestDB.config['omejdn'], response

    # Write Custom Section
    testsection = { 'testkey' => 'testvalue' }
    put '/api/admin/v2/config/testsection', testsection.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?

    # Read it back
    get '/api/admin/v2/config/testsection', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert JSON::Validator.validate(SCHEMA_CONFIG, (response = JSON.parse(last_response.body)))
    assert_equal testsection, response
  end

  # ---------- KEYS ----------

  def test_keys
    # Get Omejdn's Core Key Material (Should be generated, since we got a token above)
    get '/api/admin/v2/keys/omejdn', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    schema_keys_array = { 'type' => 'array', 'items' => SCHEMA_KEYS }
    assert JSON::Validator.validate(schema_keys_array, (response = JSON.parse(last_response.body)))
    # TODO: Verify actual key

    # Get Omejdn's Main Signing Key (Should be generated, since we got a token above)
    get '/api/admin/v2/keys/omejdn/omejdn', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert JSON::Validator.validate(SCHEMA_KEYS, (response = JSON.parse(last_response.body)))
    # TODO: Verify actual key

    # Write Custom Key in Custom Target
    testkey = OpenSSL::PKey::RSA.new 2048
    payload = { 'sk' => testkey.to_pem, 'pk' => testkey.public_key.to_pem }
    put '/api/admin/v2/keys/testtargettype/testtarget', payload.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?

    # Read it back
    get '/api/admin/v2/keys/testtargettype/testtarget', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert JSON::Validator.validate(SCHEMA_KEYS, (response = JSON.parse(last_response.body)))
    assert_equal payload, response
  end

  # ---------- USERS ----------

  def test_user
    # Get the full list of users
    get '/api/admin/v2/user', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    schema_user_array = { 'type' => 'array', 'items' => SCHEMA_USER }
    assert JSON::Validator.validate(schema_user_array, (response = JSON.parse(last_response.body)))
    expected_response = TestSetup.users.map {|u| AdminAPIv2Plugin.pack_user(u) }
    assert_equal expected_response, response

    # Add a new user
    payload = {
      'password' => 'alles wahr',
      'attributes' => {
        'seemann' => {'value' => true},
        'lügner' => { 'value' => false, 'dynamic' => true }
      },
      'consent' => {
        'biene_maja' => ['profile']
      }
    }
    put '/api/admin/v2/user/blaubaer', payload.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?
    get '/api/admin/v2/user/blaubaer', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert JSON::Validator.validate(SCHEMA_USER, (response = JSON.parse(last_response.body)))
    assert_equal 'blaubaer', response.delete('username')
    payload.delete('password')
    response.delete('backend')
    assert_equal payload, response

    # Update the user
    payload.delete('consent')
    payload['attributes']['seemann']['value'] = 'aye'
    put '/api/admin/v2/user/blaubaer', payload.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/admin/v2/user/blaubaer', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert JSON::Validator.validate(SCHEMA_USER, (response = JSON.parse(last_response.body)))
    assert_equal 'aye', response.dig('attributes','seemann','value')
    assert response.dig('consent', 'biene_maja')

    # Delete the user
    delete '/api/admin/v2/user/blaubaer', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/admin/v2/user/blaubaer', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.not_found?
  end

  # ---------- CLIENTS ----------

  def test_client
    # Get the full list of clients
    get '/api/admin/v2/client', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    schema_client_array = { 'type' => 'array', 'items' => SCHEMA_CLIENT }
    assert JSON::Validator.validate(schema_client_array, (response = JSON.parse(last_response.body)))
    expected_response = TestSetup.clients.map{|c| AdminAPIv2Plugin.pack_client(c) }
    assert_equal expected_response, response

    # Add a new client
    payload = {
      'client_secret' => 'super-secret',
      'grant_types' => ['authorization_code'],
      'token_endpoint_auth_method' => 'client_secret_post',
      'redirect_uris' => ['https://example.org/oauth/cb'],
      'attributes' => {}
    }
    put '/api/admin/v2/client/simpletestclient', payload.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?
    get '/api/admin/v2/client/simpletestclient', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert JSON::Validator.validate(SCHEMA_CLIENT, (response = JSON.parse(last_response.body)))
    assert_equal 'simpletestclient', response.delete('client_id')
    assert_equal payload, response

    # Update the client
    payload = { 'attributes' => { 'coolclient' => { 'value' => true } } }
    put '/api/admin/v2/client/simpletestclient', payload.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/admin/v2/client/simpletestclient', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert JSON::Validator.validate(SCHEMA_CLIENT, (response = JSON.parse(last_response.body)))
    assert_equal payload['attributes'], response['attributes']
    assert_equal 'super-secret', response['client_secret']

    # Delete the client
    delete '/api/admin/v2/client/simpletestclient', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/admin/v2/client/simpletestclient', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.not_found?
  end

  # ---------- CLIENT KEYS ----------

  def test_client_keys
    # Generate a new test certificate
    key  = OpenSSL::PKey::RSA.new 2048
    cert = OpenSSL::X509::Certificate.new
    cert.version    = 2
    cert.serial     = 0
    cert.not_before = Time.now
    cert.not_after  = Time.now + 3600
    cert.public_key = key.public_key
    cert.subject    = OpenSSL::X509::Name.parse 'CN=test/DC=test'
    cert.issuer     = OpenSSL::X509::Name.parse 'CN=test/DC=test'
    cert.sign key, OpenSSL::Digest::SHA1.new

    # Add the certificate
    client = @client
    put "/api/admin/v2/client/#{client.client_id}/certificate", cert.to_pem.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?
    get "/api/admin/v2/client/#{client.client_id}/certificate", {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    schema_pem_cert = schema_pem('CERTIFICATE')
    assert JSON::Validator.validate(schema_pem_cert, (response = JSON.parse(last_response.body)))
    assert_equal cert.to_pem, response

    # Delete the certificate
    delete "/api/admin/v2/client/#{client.client_id}/certificate", {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get "/api/admin/v2/client/#{client.client_id}/certificate", {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.not_found?
  end

end
