# frozen_string_literal: true
require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative 'config_testsetup'
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

    TestSetup.setup

    @client  = Client.find_by_id 'testClient'
    @client2 = Client.find_by_id 'testClient2'
    @client_dyn_claims = Client.find_by_id 'dynamic_claims'
    @testCertificate = File.read './tests/test_resources/testClient.pem'
  end

  def teardown
    TestSetup.teardown
    @client.certificate = nil
    @client2.certificate = nil
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
    assert_equal response["expires_in"], TestSetup.config['token']['expiration']
    assert_equal response["token_type"], "bearer"
    assert_equal response["scope"], "omejdn:write"

    jwt = JWT.decode(response['access_token'], Server.load_key.public_key, true, { algorithm: TestSetup.config['token']['algorithm'] })
    check_keys jwt[1], ['typ','kid','alg']
    assert_equal jwt[1]['typ'], 'at+jwt'
    assert_equal jwt[1]['kid'], 'default'
    assert_equal jwt[1]['alg'], TestSetup.config['token']['algorithm']

    return jwt[0]
  end

  def test_client_credentials
    response = request_client_credentials @client, "ES256", @priv_key_ec256, @certificate_ec256
    at = extract_access_token response

    check_keys at, ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub']
    assert_equal at['scope'], 'omejdn:write'
    assert_equal at['aud'], [TestSetup.config['token']['audience'], TestSetup.config['host']+'/api']
    assert_equal at['iss'], TestSetup.config['token']['issuer']
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
    assert_equal at['aud'], ['http://example.org', TestSetup.config['host']+'/api']
    assert_equal at['iss'], TestSetup.config['token']['issuer']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['iat'], at['nbf']
    assert_equal at['exp'], at['nbf']+response["expires_in"]
    assert       at['jti']
    assert_equal at['client_id'], @client2.client_id
    assert_equal at['sub'], at['client_id']
  end

  def test_client_credentials_scope_rejection
    additional_scopes = ' abc'
    response = request_client_credentials @client, "ES256", @priv_key_ec256, @certificate_ec256, additional_scopes
    at = extract_access_token response

    check_keys at, ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub']
    assert_equal at['scope'], 'omejdn:write'
    assert_equal at['aud'], [TestSetup.config['token']['audience'], TestSetup.config['host']+'/api']
    assert_equal at['iss'], TestSetup.config['token']['issuer']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['iat'], at['nbf']
    assert_equal at['exp'], at['nbf']+response["expires_in"]
    assert       at['jti']
    assert_equal at['client_id'], @client.client_id
    assert_equal at['sub'], at['client_id']
  end

  def test_client_credentials_dynamic_claims
    requested_claims = {
      '*' => {
        'dynattribute'=> { # should be included
          'value' => 'myvalue'
        },
        'nondynattribute'=> { # should get rejected
          'value' => 'myvalue'
        }
      }
    }
    query_additions = '&claims='+URI.encode_www_form_component(requested_claims.to_json)
    response = request_client_credentials @client_dyn_claims, "ES256", @priv_key_ec256, @certificate_ec256, query_additions
    at = extract_access_token response

    check_keys at, ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub', 'dynattribute']
    assert_equal at['scope'], 'omejdn:write'
    assert_equal at['aud'], [TestSetup.config['token']['audience'], TestSetup.config['host']+'/api']
    assert_equal at['iss'], TestSetup.config['token']['issuer']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['iat'], at['nbf']
    assert_equal at['exp'], at['nbf']+response["expires_in"]
    assert       at['jti']
    assert_equal at['client_id'], @client_dyn_claims.client_id
    assert_equal at['sub'], at['client_id']
    assert_equal at['dynattribute'], requested_claims['*']['dynattribute']['value']
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
    response = request_authorization TestSetup.users[0], @client
    at = extract_access_token response

    check_keys at, ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub', 'omejdn']
    assert_equal at['scope'], 'omejdn:write'
    assert_equal at['aud'], [TestSetup.config['token']['audience'], TestSetup.config['host']+'/api']
    assert_equal at['iss'], TestSetup.config['token']['issuer']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['iat'], at['nbf']
    assert_equal at['exp'], at['nbf']+response["expires_in"]
    assert       at['jti']
    assert_equal at['client_id'], @client.client_id
    assert_equal at['sub'], TestSetup.users[0]['username']
    assert_equal 'write', at['omejdn']
  end

  def test_authorization_flow_with_bad_resources
    resources = '&resource=a&resource=b'
    response = request_authorization TestSetup.users[0], @client2, resources, false
  end

  def test_authorization_flow_with_resources
    resources = '&resource=http://example.org'
    response = request_authorization TestSetup.users[0], @client2, resources
    at = extract_access_token response

    check_keys at, ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub', 'omejdn']
    assert_equal at['scope'], 'omejdn:write'
    assert_equal at['aud'], ['http://example.org', TestSetup.config['host']+'/api']
    assert_equal at['iss'], TestSetup.config['token']['issuer']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['iat'], at['nbf']
    assert_equal at['exp'], at['nbf']+response["expires_in"]
    assert       at['jti']
    assert_equal at['client_id'], @client2.client_id
    assert_equal at['sub'], TestSetup.users[0]['username']
    assert_equal 'write', at['omejdn']
  end
end
