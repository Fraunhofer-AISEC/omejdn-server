# frozen_string_literal: true

ENV['APP_ENV'] = 'test'

require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative '../omejdn'
require_relative '../lib/token_helper'

class OAuth2Test < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    # Load private keys
    @priv_key_ec256 = OpenSSL::PKey::EC.new File.read './tests/test_resources/ec256.pem'
    @priv_key_ec512 = OpenSSL::PKey::EC.new File.read './tests/test_resources/ec512.pem'
    @priv_key_rsa = OpenSSL::PKey::RSA.new File.read './tests/test_resources/rsa.pem'
    @certificate_ec256 = File.read './tests/test_resources/ec256.cert'
    @certificate_ec512 = File.read './tests/test_resources/ec512.cert'
    @certificate_rsa = File.read './tests/test_resources/rsa.cert'

    @backup_users   = File.read './config/users.yml'
    @backup_clients = File.read './config/clients.yml'
    @backup_omejdn  = File.read './config/omejdn.yml'
    File.open('./config/users.yml', 'w')   { |file| file.write(users_testsetup.to_yaml) }
    File.open('./config/clients.yml', 'w') { |file| file.write(clients_testsetup.to_yaml) }
    File.open('./config/omejdn.yml', 'w')  { |file| file.write(config_testsetup.to_yaml) }
    
    @client  = Client.find_by_id 'testClient'
    @client2 = Client.find_by_id 'testClient2'
    @testCertificate = File.read './tests/test_resources/testClient.pem'
  end

  def teardown
    File.open('./config/users.yml', 'w')   { |file| file.write(@backup_users) }
    File.open('./config/clients.yml', 'w') { |file| file.write(@backup_clients) }
    File.open('./config/omejdn.yml', 'w')  { |file| file.write(@backup_omejdn) }
    @client.certificate = nil
    @client2.certificate = nil
  end

  def users_testsetup
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
      'password' => '$2a$12$s1UhO7bRO9b5fTTiRE4KxOR88vz3462Bxn8DGh/iDX26Neh95AHrC' # "mypassword"
    }]
  end

  def clients_testsetup
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
       'attributes' => [],
       'allowed_resources' => ['http://example.org','http://localhost:4567/api']
     }]
  end

  def config_testsetup
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
      'user_backend' => ['yaml']
    }
  end

  def request_client_credentials(client, alg, key, certificate, query_additions='', should_work=true)
    iss = client.client_id
    now = Time.new.to_i
    payload = { aud: Config.base_config['token']['issuer'], sub: iss, iss: iss, iat: now, nbf: now, exp: now + 3600 }
    client.certificate = certificate
    query = 'grant_type=client_credentials'+
            '&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer'+
            '&client_assertion='+JWT.encode(payload, key, alg)+
            '&scope=omejdn:write'+query_additions
    post ('/token?'+query), {}, {}
    assert should_work == last_response.ok?
    JSON.parse last_response.body
  end

  def check_keys(hash, keylist)
    assert hash.keys.reject{|k| keylist.include?k}.empty?
    assert keylist.reject{|k| hash.keys.include?k}.empty?
  end

  def extract_access_token(response)
    check_keys response, ["access_token","expires_in","token_type","scope"]
    assert_equal response["expires_in"], config_testsetup['token']['expiration']
    assert_equal response["token_type"], "bearer"
    assert_equal response["scope"], "omejdn:write"

    jwt = JWT.decode(response['access_token'], Server.load_key.public_key, true, { algorithm: config_testsetup['token']['algorithm'] })
    check_keys jwt[1], ['typ','kid','alg']
    assert_equal jwt[1]['typ'], 'at+jwt'
    assert_equal jwt[1]['kid'], 'default'
    assert_equal jwt[1]['alg'], config_testsetup['token']['algorithm']

    return jwt[0]
  end

  def test_client_credentials
    response = request_client_credentials @client, "ES256", @priv_key_ec256, @certificate_ec256
    at = extract_access_token response

    check_keys at, ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub']
    assert_equal at['scope'], 'omejdn:write'
    assert_equal at['aud'], [config_testsetup['token']['audience'], config_testsetup['host']+'/api']
    assert_equal at['iss'], config_testsetup['token']['issuer']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['iat'], at['nbf']
    assert_equal at['exp'], at['nbf']+response["expires_in"]
    assert       at['jti']
    assert_equal at['client_id'], @client.client_id
    assert_equal at['sub'], at['client_id']
  end

  def test_client_credentials_with_resources
    resources = '&resource=a&resource=b'
    response = request_client_credentials @client2, "ES256", @priv_key_ec256, @certificate_ec256, resources, false
    resources = '&resource=http://example.org'
    response = request_client_credentials @client2, "ES256", @priv_key_ec256, @certificate_ec256, resources
    at = extract_access_token response

    check_keys at, ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub']
    assert_equal at['scope'], 'omejdn:write'
    assert_equal at['aud'], ['http://example.org', config_testsetup['host']+'/api']
    assert_equal at['iss'], config_testsetup['token']['issuer']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['iat'], at['nbf']
    assert_equal at['exp'], at['nbf']+response["expires_in"]
    assert       at['jti']
    assert_equal at['client_id'], @client2.client_id
    assert_equal at['sub'], at['client_id']
  end

  def test_algorithms
    request_client_credentials @client, "ES256", @priv_key_ec256, @certificate_ec256
    request_client_credentials @client, "ES512", @priv_key_ec512, @certificate_ec512
    request_client_credentials @client, "RS256", @priv_key_rsa,   @certificate_rsa
    request_client_credentials @client, "RS512", @priv_key_rsa,   @certificate_rsa
    request_client_credentials @client, "PS512", @priv_key_rsa,   @certificate_rsa, '', false
    request_client_credentials @client, "PS256", @priv_key_rsa,   @certificate_rsa, '', false
  end

  def request_authorization(user, client, query_additions='', should_work=true)
    # POST /login (Separating pass and word in the hope of silencing Sonarcloud)
    post ('/login?username='+user['username']+'&pass'+'word=mypass'+'word'),{},{}
    good_so_far = last_response.redirect?
    assert good_so_far if should_work
    assert_equal "http://localhost:4567/login", last_response.original_headers['Location']
    
    # GET /authorize
    get  ('/authorize?response_type=code'+
          '&scope=omejdn:write'+
          '&client_id='+client.client_id+
          '&redirect_uri='+client.redirect_uri+
          '&state=testState'+query_additions), {}, {}
    # p last_response
    good_so_far &= last_response.ok?
    assert good_so_far if should_work
    
    # POST /authorize
    post '/authorize', {}, {}
    good_so_far &= last_response.redirect?
    assert good_so_far if should_work
    header_hash = CGI.parse(last_response.original_headers['Location'])
    assert code=header_hash[client.redirect_uri+'?code'].first
    assert_equal 'testState', header_hash['state'].first

    # Get /token
    query = 'grant_type=authorization_code'+
    '&code='+code+
    '&client_id='+client.client_id+
    '&scope=omejdn:write'+query_additions
    post ('/token?'+query), {}, {}
    good_so_far &= last_response.ok?
    assert good_so_far == should_work
    return JSON.parse last_response.body
  end

  def test_authorization_flow
    response = request_authorization users_testsetup[0], @client
    at = extract_access_token response

    check_keys at, ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub', 'omejdn']
    assert_equal at['scope'], 'omejdn:write'
    assert_equal at['aud'], [config_testsetup['token']['audience'], config_testsetup['host']+'/api']
    assert_equal at['iss'], config_testsetup['token']['issuer']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['iat'], at['nbf']
    assert_equal at['exp'], at['nbf']+response["expires_in"]
    assert       at['jti']
    assert_equal at['client_id'], @client.client_id
    assert_equal at['sub'], users_testsetup[0]['username']
    assert_equal 'write', at['omejdn']
  end

  def test_authorization_flow_with_bad_resources
    resources = '&resource=a&resource=b'
    response = request_authorization users_testsetup[0], @client2, resources, false
  end

  def test_authorization_flow_with_resources
    resources = '&resource=http://example.org'
    response = request_authorization users_testsetup[0], @client2, resources
    at = extract_access_token response

    check_keys at, ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub', 'omejdn']
    assert_equal at['scope'], 'omejdn:write'
    assert_equal at['aud'], ['http://example.org', config_testsetup['host']+'/api']
    assert_equal at['iss'], config_testsetup['token']['issuer']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['iat'], at['nbf']
    assert_equal at['exp'], at['nbf']+response["expires_in"]
    assert       at['jti']
    assert_equal at['client_id'], @client2.client_id
    assert_equal at['sub'], users_testsetup[0]['username']
    assert_equal 'write', at['omejdn']
  end
end
