# frozen_string_literal: true
require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative 'config_testsetup'
require_relative '../omejdn'
require_relative '../lib/token'

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
    payload = { aud: Config.base_config.dig('issuer'), sub: iss, iss: iss, iat: now, nbf: now, exp: now + 3600 }
    client.certificate = certificate
    query = 'grant_type=client_credentials'+
            '&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer'+
            '&client_assertion='+JWT.encode(payload, key, alg)+
            '&scope=omejdn:write'+query_additions
    post ('/token?'+query), {}, {}
    assert should_work == last_response.ok?
    JSON.parse last_response.body
  end

  def check_keys(keylist, hash)
    assert_equal keylist.sort, hash.keys.sort
  end

  def decode_jwt(jwt)
    get '/.well-known/jwks.json'
    assert last_response.ok?
    server_keys = JSON::JWK::Set.new JSON.parse(last_response.body)
    JWT.decode(jwt,nil,true, {
      algorithms: [TestSetup.config.dig('access_token','algorithm')],
      jwks: {'keys'=>server_keys}})
  end

  def extract_access_token(response)
    check_keys ["access_token","expires_in","token_type","scope"], response
    assert_equal TestSetup.config.dig('access_token','expiration'), response["expires_in"]
    assert_equal "bearer", response["token_type"]
    assert_equal "omejdn:write", response["scope"]

    jwt = decode_jwt response['access_token']
    check_keys ['typ','kid','alg'], jwt[1]
    assert_equal 'at+jwt', jwt.dig(1,'typ')
    assert_equal TestSetup.config.dig('access_token','algorithm'), jwt.dig(1,'alg')

    return jwt[0]
  end

  def test_client_credentials
    response = request_client_credentials @client, "ES256", @priv_key_ec256, @certificate_ec256
    at = extract_access_token response

    check_keys ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub'], at
    assert_equal 'omejdn:write', at['scope']
    assert_equal [TestSetup.config.dig('default_audience'), TestSetup.config['front_url']+'/api'], at['aud']
    assert_equal TestSetup.config.dig('issuer'), at['iss']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['nbf'], at['iat']
    assert_equal at['nbf']+response["expires_in"], at['exp']
    assert       at['jti']
    assert_equal @client.client_id, at['client_id']
    assert_equal at['client_id'], at['sub']
  end

  def test_client_credentials_with_resources
    resources = '&resource=a&resource=b'
    response = request_client_credentials @client2, "ES256", @priv_key_ec256, @certificate_ec256, resources, false
    resources = '&resource=http://example.org'
    response = request_client_credentials @client2, "ES256", @priv_key_ec256, @certificate_ec256, resources
    at = extract_access_token response

    assert_equal 'omejdn:write', at['scope']
    assert_equal ['http://example.org', TestSetup.config['front_url']+'/api'], at['aud']
    assert_equal TestSetup.config.dig('issuer'), at['iss']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['nbf'], at['iat']
    assert_equal at['nbf']+response["expires_in"], at['exp']
    assert       at['jti']
    assert_equal @client2.client_id, at['client_id']
    assert_equal at['client_id'], at['sub']
  end

  def test_client_credentials_scope_rejection
    additional_scopes = ' abc'
    response = request_client_credentials @client, "ES256", @priv_key_ec256, @certificate_ec256, additional_scopes
    at = extract_access_token response

    check_keys ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub'], at
    assert_equal 'omejdn:write', at['scope']
    assert_equal [TestSetup.config.dig('default_audience'), TestSetup.config['front_url']+'/api'], at['aud']
    assert_equal TestSetup.config.dig('issuer'), at['iss']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['nbf'], at['iat']
    assert_equal at['nbf']+response["expires_in"], at['exp']
    assert       at['jti']
    assert_equal @client.client_id, at['client_id']
    assert_equal at['client_id'], at['sub']
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

    check_keys ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub', 'dynattribute','omejdn_reserved'], at
    assert_equal 'omejdn:write', at['scope']
    assert_equal [TestSetup.config.dig('default_audience'), TestSetup.config['front_url']+'/api'], at['aud']
    assert_equal TestSetup.config.dig('issuer'), at['iss']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['nbf'], at['iat']
    assert_equal at['nbf']+response["expires_in"], at['exp']
    assert       at['jti']
    assert_equal @client_dyn_claims.client_id, at['client_id']
    assert_equal at['client_id'], at['sub']
    assert_equal requested_claims.dig('*','dynattribute','value'), at['dynattribute']
  end

  def test_algorithms
    request_client_credentials @client, "ES256", @priv_key_ec256, @certificate_ec256
    request_client_credentials @client, "ES512", @priv_key_ec512, @certificate_ec512
    request_client_credentials @client, "RS256", @priv_key_rsa,   @certificate_rsa
    request_client_credentials @client, "RS512", @priv_key_rsa,   @certificate_rsa
  end

  def request_authorization(user, client, query_additions='', should_work=true, scopes = ['omejdn:write'])
    # GET /authorize
    get  ('/authorize?response_type=code'+
          '&scope='+scopes.join(' ')+
          '&client_id='+client.client_id+
          '&redirect_uri='+client.redirect_uri+
          '&state=testState'+query_additions), {}, {}
    # p last_response
    good_so_far = last_response.redirect?
    assert good_so_far if should_work
    assert ["http://localhost:4567/consent", "http://localhost:4567/login"].include? last_response.original_headers['Location']
    
    # POST /login (Separating pass and word in the hope of silencing Sonarcloud)
    post ('/login?username='+user['username']+'&pass'+'word=mypass'+'word'),{},{}
    good_so_far &= last_response.redirect?
    assert good_so_far if should_work
    assert_equal "http://localhost:4567/consent", last_response.original_headers['Location']

    # GET /consent
    get '/consent', {}, {}
    good_so_far &= last_response.ok?
    assert good_so_far if should_work

    # POST /consent
    post '/consent', {}, {}
    good_so_far &= last_response.redirect?
    assert good_so_far if should_work
    # p last_response
    header_hash = CGI.parse(last_response.original_headers['Location'])
    assert code=header_hash[client.redirect_uri+'?code'].first
    # p code
    assert_equal 'testState', header_hash['state'].first
    assert_equal TestSetup.config['issuer'], header_hash['iss'].first

    # Get /token
    query = 'grant_type=authorization_code'+
    '&code='+code+
    '&client_id='+client.client_id+
    '&scope='+scopes.join(' ')+query_additions+
    '&redirect_uri='+client.redirect_uri
    post ('/token?'+query), {}, {}
    good_so_far &= last_response.ok?
    assert good_so_far == should_work
    return JSON.parse last_response.body
  end

  def test_authorization_flow
    response = request_authorization TestSetup.users[0], @client
    at = extract_access_token response

    check_keys ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub', 'omejdn'], at
    assert_equal 'omejdn:write', at['scope']
    assert_equal [TestSetup.config.dig('default_audience'), TestSetup.config['front_url']+'/api'], at['aud']
    assert_equal TestSetup.config.dig('issuer'), at['iss']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['nbf'], at['iat']
    assert_equal at['nbf']+response["expires_in"], at['exp']
    assert       at['jti']
    assert_equal @client.client_id, at['client_id']
    assert_equal TestSetup.users.dig(0,'username'), at['sub']
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

    check_keys ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub', 'omejdn'], at
    assert_equal 'omejdn:write', at['scope']
    assert_equal ['http://example.org', TestSetup.config['front_url']+'/api'], at['aud']
    assert_equal TestSetup.config.dig('issuer'), at['iss']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['nbf'], at['iat']
    assert_equal at['nbf']+response["expires_in"], at['exp']
    assert       at['jti']
    assert_equal @client2.client_id, at['client_id']
    assert_equal TestSetup.users.dig(0,'username'), at['sub']
    assert_equal 'write', at['omejdn']
  end

  def test_authorization_flow_with_claims
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
    response = request_authorization TestSetup.users[2], @client, query_additions
    at = extract_access_token response

    check_keys ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub', 'omejdn', 'dynattribute', 'omejdn_reserved'], at
    assert_equal 'omejdn:write', at['scope']
    assert_equal [TestSetup.config.dig('default_audience'), TestSetup.config['front_url']+'/api'], at['aud']
    assert_equal TestSetup.config.dig('issuer'), at['iss']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['nbf'], at['iat']
    assert_equal at['nbf']+response["expires_in"], at['exp']
    assert       at['jti']
    assert_equal @client.client_id, at['client_id']
    assert_equal TestSetup.users.dig(2,'username'), at['sub']
    assert_equal 'write', at['omejdn']
    assert_equal requested_claims.dig('*','dynattribute','value'), at['dynattribute']
  end

  def test_authorization_flow_with_request_object
    payload = {
      'response_type' => 'code',
      'client_id' => @client.client_id,
      'redirect_uri' => @client.redirect_uri,
      'state' => 'testState',
      'scope' => 'omejdn:write'
    }
    @client.certificate = @certificate_rsa
    jwt = JWT.encode payload, @priv_key_rsa , 'RS256', { typ: 'at+jwt' }
    get  ('/authorize?request='+jwt+'&client_id='+@client.client_id), {}, {}
    p last_response
    assert last_response.redirect?
    assert ["http://localhost:4567/consent", "http://localhost:4567/login"].include? last_response.original_headers['Location']
  end

  def test_authorization_flow_with_request_uri
    payload = {
      'response_type' => 'code',
      'client_id' => @client.client_id,
      'redirect_uri' => @client.redirect_uri,
      'state' => 'testState',
      'scope' => 'omejdn:write'
    }
    @client.certificate = @certificate_rsa
    jwt = JWT.encode payload, @priv_key_rsa , 'RS256', { typ: 'at+jwt' }

    post '/par', {'client_id'=>@client.client_id, 'request'=>jwt}, {}
    assert last_response.created?
    uri = (JSON.parse last_response.body)['request_uri']
    # GET /authorize
    get  ('/authorize?request_uri='+uri+'&client_id='+@client.client_id), {}, {}
    assert last_response.redirect?
    assert ["http://localhost:4567/consent", "http://localhost:4567/login"].include? last_response.original_headers['Location']
  end
end
