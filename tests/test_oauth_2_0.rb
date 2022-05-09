# frozen_string_literal: true
require 'test/unit'
require 'rack/test'
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
    @certificate_ec256 = OpenSSL::X509::Certificate.new File.read('./tests/test_resources/ec256.cert')
    @certificate_ec512 = OpenSSL::X509::Certificate.new File.read('./tests/test_resources/ec512.cert')
    @certificate_rsa = OpenSSL::X509::Certificate.new File.read('./tests/test_resources/rsa.cert')

    TestSetup.setup

    @client_private_key_jwt     = Client.find_by_id 'private_key_jwt_client'
    @client_client_secret_basic = Client.find_by_id 'client_secret_basic_client'
    @client_client_secret_post  = Client.find_by_id 'client_secret_post_client'
    @public_client              = Client.find_by_id 'publicClient'
    @resource_client            = Client.find_by_id 'resourceClient'
    @client_dyn_claims          = Client.find_by_id 'dynamic_claims'
    @testCertificate = File.read './tests/test_resources/testClient.pem'
  end

  def teardown
    @client_private_key_jwt.certificate = nil
  end

  # tries to request a token, returns the corresponding response or nil
  def request_token(grant_type, client, scope, code: nil, pkce: nil, cert: nil, key: nil, alg: nil, auth: true, query_additions: nil)
    params = {
      :grant_type => grant_type,
      :client_id => client.client_id,
      :scope => scope,
      :code => code
  }.merge(query_additions || {})
    headers = {}
    if auth
      case client.metadata['token_endpoint_auth_method']
      when 'private_key_jwt'
        params.merge! ({
          :client_assertion_type => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          :client_assertion => get_private_key_jwt(client, alg, key, cert)
        })
      when 'client_secret_basic'
        headers.merge! ({
          'HTTP_AUTHORIZATION' => "Basic #{Base64.strict_encode64("#{client.client_id}:#{client.metadata['client_secret']}")}"
        })
      when 'client_secret_post'
        params.merge! ({ :client_secret => client.metadata['client_secret'] })
      end
    end
    post '/token', params.compact, headers.compact
    last_response.ok? ? JSON.parse(last_response.body) : nil
  end

  def get_private_key_jwt(client, alg, key, certificate)
    client.certificate = certificate
    iss = client.client_id
    now = Time.new.to_i
    payload = { aud: Config.base_config.dig('issuer'), sub: iss, iss: iss, iat: now, nbf: now, exp: now + 3600 }
    JWT.encode(payload, key, alg)
  end

  def check_keys(keylist, hash)
    assert_equal keylist.sort, hash.keys.sort
  end

  def extract_access_token(response)
    check_keys ["access_token","expires_in","token_type","scope"], response
    assert_equal TestSetup.config.dig('access_token','expiration'), response["expires_in"]
    assert_equal "bearer", response["token_type"]
    assert_equal "omejdn:write", response["scope"]

    get '/jwks.json'
    assert last_response.ok?
    server_keys = JSON.parse(last_response.body)
    jwt = JWT.decode(response['access_token'],nil,true, {
      algorithms: [TestSetup.config.dig('access_token','algorithm')],
      jwks: server_keys})
    check_keys ['typ','kid','alg'], jwt[1]
    assert_equal 'at+jwt', jwt.dig(1,'typ')
    assert_equal TestSetup.config.dig('access_token','algorithm'), jwt.dig(1,'alg')

    return jwt[0]
  end

  def test_client_credentials_grant
    response = request_token 'client_credentials', @public_client, 'omejdn:write'
    assert response
    at = extract_access_token response

    check_keys ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub'], at
    assert_equal 'omejdn:write', at['scope']
    assert_equal [TestSetup.config.dig('default_audience'), TestSetup.config['front_url']+'/api'].flatten, at['aud']
    assert_equal TestSetup.config.dig('issuer'), at['iss']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['nbf'], at['iat']
    assert_equal at['nbf']+response["expires_in"], at['exp']
    assert       at['jti']
    assert_equal @public_client.client_id, at['client_id']
    assert_equal at['client_id'], at['sub']
  end

  def test_client_authentication
    # sucessful
    assert request_token 'client_credentials', @public_client,              'omejdn:write'
    assert request_token 'client_credentials', @client_client_secret_basic, 'omejdn:write'
    assert request_token 'client_credentials', @client_client_secret_post,  'omejdn:write'
    assert request_token 'client_credentials', @client_private_key_jwt,     'omejdn:write', cert:@certificate_ec256, key:@priv_key_ec256, alg:"ES256"

    # no auth
    assert (request_token 'client_credentials', @client_client_secret_basic, 'omejdn:write', auth: false).nil?
    assert (request_token 'client_credentials', @client_client_secret_post,  'omejdn:write', auth: false).nil?
    assert (request_token 'client_credentials', @client_private_key_jwt,     'omejdn:write', auth: false).nil?

    # wrong secret
    @client_client_secret_basic.metadata['client_secret'] = 'wrong'
    @client_client_secret_post .metadata['client_secret'] = 'wrong'
    assert (request_token 'client_credentials', @client_client_secret_basic, 'omejdn:write').nil?
    assert (request_token 'client_credentials', @client_client_secret_post,  'omejdn:write').nil?

    # wrong key
    assert (request_token 'client_credentials', @client_private_key_jwt,     'omejdn:write', cert:@certificate_ec512, key:@priv_key_ec256, alg:"ES256").nil?
  end

  def test_client_authentication_jwt_algorithms
    assert request_token 'client_credentials', @client_private_key_jwt,     'omejdn:write', cert:@certificate_ec256, key:@priv_key_ec256, alg:"ES256"
    assert request_token 'client_credentials', @client_private_key_jwt,     'omejdn:write', cert:@certificate_ec512, key:@priv_key_ec512, alg:"ES512"
    assert request_token 'client_credentials', @client_private_key_jwt,     'omejdn:write', cert:@certificate_rsa,   key:@priv_key_rsa,   alg:"RS256"
    assert request_token 'client_credentials', @client_private_key_jwt,     'omejdn:write', cert:@certificate_rsa,   key:@priv_key_rsa,   alg:"RS512"
  end

  def test_client_credentials_with_resources
    resources = { 'resource' => ['a','b'] }
    assert (request_token 'client_credentials', @resource_client, 'omejdn:write', query_additions: resources).nil?
    resources = { 'resource' => 'http://example.org' }
    response = request_token 'client_credentials', @resource_client, 'omejdn:write', query_additions: resources
    assert response
    at = extract_access_token response
    assert_equal ['http://example.org', TestSetup.config['front_url']+'/api'], at['aud']
  end

  def test_client_credentials_scope_rejection
    response = request_token 'client_credentials', @public_client, 'omejdn:write wrong'
    assert response
    at = extract_access_token response
    assert_equal 'omejdn:write', at['scope']
  end

#  def test_client_credentials_dynamic_claims
#    claims = {
#      '*' => {
#        'dynattribute'=> { # should be included
#          'value' => 'myvalue'
#        },
#        'nondynattribute'=> { # should get rejected
#          'value' => 'myvalue'
#        }
#      }
#    }
#    query_additions = { 'claims' => claims.to_json }
#    response = request_token 'client_credentials', @client_dyn_claims, 'omejdn:write', query_additions: query_additions
#    assert response
#    at = extract_access_token response
#    assert_equal claims.dig('*','dynattribute','value'), at['dynattribute']
#    assert_equal nil, at['nondynattribute']
#  end

  # Returns an authorization code or nil
  def request_authorize(user, client, scope, state: 'teststate', query_additions: nil, pkce_challenge: nil)
    # Initial authorization redirect
    params = {
      :response_type => 'code',
      :client_id => client.client_id,
      :redirect_uri => [*client.metadata['redirect_uris']].first,
      :state => state,
      :scope => scope
    }.merge(query_additions || {})
    get  ("/authorize?#{URI.encode_www_form(params.compact)}"), {}, {}
    return nil unless last_response.redirect?
    return nil unless ["http://localhost:4567/consent", "http://localhost:4567/login"].include? last_response.original_headers['Location']

    # login
    params = {
      'username' => user['username'],
      'password' => 'mypassword'
    }
    get '/login', {}, {}
    return nil unless last_response.ok?
    post '/login/exec', params.compact, {}
    return nil unless last_response.redirect?
    return nil unless ["http://localhost:4567/consent"].include? last_response.original_headers['Location']

    # consent
    get '/consent', {}, {}
    return nil unless last_response.ok?
    post '/consent/exec', {}, {}
    return nil unless last_response.redirect?

    # extract code
    response_params = URI.decode_www_form(URI(last_response.original_headers['Location']).query).to_h
    code=response_params['code']
    return nil unless code
    assert_equal state, response_params['state']
    assert_equal TestSetup.config['issuer'], response_params['iss']

    code
  end

  def test_authorization_code_grant
    code = request_authorize TestSetup.users[0], @public_client, 'omejdn:write'
    assert code
    query_additions = {
      'redirect_uri' => [*@public_client.metadata['redirect_uris']].first
    }
    response = request_token 'authorization_code', @public_client, 'omejdn:write', code: code, query_additions: query_additions
    assert response
    at = extract_access_token response

    check_keys ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub'], at
    assert_equal 'omejdn:write', at['scope']
    assert_equal [TestSetup.config.dig('default_audience'), TestSetup.config['front_url']+'/api'].flatten, at['aud']
    assert_equal TestSetup.config.dig('issuer'), at['iss']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['nbf'], at['iat']
    assert_equal at['nbf']+response["expires_in"], at['exp']
    assert       at['jti']
    assert_equal @public_client.client_id, at['client_id']
    assert_equal TestSetup.users.dig(0,'username'), at['sub']
  end

  def test_authorization_flow_with_bad_resources
    resources = { 'resource' => ['a','b'] }
    assert (request_authorize TestSetup.users[0], @resource_client, 'omejdn:write', query_additions: resources).nil?
  end

  def test_authorization_flow_with_resources
    resources = { 'resource' => 'http://example.org' }
    code = request_authorize TestSetup.users[0], @resource_client, 'omejdn:write', query_additions: resources
    assert code
    query_additions = {
      'redirect_uri' => [*@public_client.metadata['redirect_uris']].first
    }
    response = request_token 'authorization_code', @resource_client, 'omejdn:write', code: code, query_additions: query_additions
    assert response
    at = extract_access_token response

    check_keys ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub'], at
    assert_equal 'omejdn:write', at['scope']
    assert_equal ['http://example.org', TestSetup.config['front_url']+'/api'], at['aud']
    assert_equal TestSetup.config.dig('issuer'), at['iss']
    assert       at['nbf'] <= Time.new.to_i
    assert_equal at['nbf'], at['iat']
    assert_equal at['nbf']+response["expires_in"], at['exp']
    assert       at['jti']
    assert_equal @resource_client.client_id, at['client_id']
    assert_equal TestSetup.users.dig(0,'username'), at['sub']
  end

#  def test_authorization_flow_with_claims
#    claims = {
#      '*' => {
#        'dynattribute'=> { # should be included
#          'value' => 'myvalue'
#        },
#        'nondynattribute'=> { # should get rejected
#          'value' => 'myvalue'
#        }
#      }
#    }
#    query_additions = { 'claims' => claims.to_json }
#    code = request_authorize TestSetup.users[2], @client_dyn_claims, 'omejdn:write', query_additions: query_additions
#    assert code
#    query_additions.merge!({
#      'redirect_uri' => [*@client_dyn_claims.metadata['redirect_uris']].first
#    })
#    response = request_token 'authorization_code', @client_dyn_claims, 'omejdn:write', code: code, query_additions: query_additions
#    assert response
#    at = extract_access_token response
#
#    check_keys ['scope','aud','iss','nbf','iat','jti','exp','client_id','sub', 'dynattribute', 'omejdn_reserved'], at
#    assert_equal 'omejdn:write', at['scope']
#    assert_equal [TestSetup.config.dig('default_audience'), TestSetup.config['front_url']+'/api'], at['aud']
#    assert_equal TestSetup.config.dig('issuer'), at['iss']
#    assert       at['nbf'] <= Time.new.to_i
#    assert_equal at['nbf'], at['iat']
#    assert_equal at['nbf']+response["expires_in"], at['exp']
#    assert       at['jti']
#    assert_equal @client_dyn_claims.client_id, at['client_id']
#    assert_equal TestSetup.users.dig(2,'username'), at['sub']
#    assert_equal 'write', at['omejdn']
#    assert_equal claims.dig('*','dynattribute','value'), at['dynattribute']
#  end

  def test_authorization_flow_with_request_object
    payload = {
      'response_type' => 'code',
      'client_id' => @client_private_key_jwt.client_id,
      'redirect_uri' => @client_private_key_jwt.metadata['redirect_uris'],
      'state' => 'testState',
      'scope' => 'omejdn:write'
    }
    @client_private_key_jwt.certificate = @certificate_rsa
    jwt = JWT.encode payload, @priv_key_rsa , 'RS256', { typ: 'at+jwt' }
    get  ('/authorize?request='+jwt+'&client_id='+@client_private_key_jwt.client_id), {}, {}
    # p last_response
    assert last_response.redirect?
    assert ["http://localhost:4567/consent", "http://localhost:4567/login"].include? last_response.original_headers['Location']
  end

  def test_authorization_flow_with_request_uri
    payload = {
      'response_type' => 'code',
      'client_id' => @client_private_key_jwt.client_id,
      'redirect_uri' => @client_private_key_jwt.metadata['redirect_uris'],
      'state' => 'testState',
      'scope' => 'omejdn:write'
    }
    @client_private_key_jwt.certificate = @certificate_rsa
    jwt = JWT.encode payload, @priv_key_rsa , 'RS256', { typ: 'at+jwt' }

    post '/par', {
      'client_id'=>@client_private_key_jwt.client_id,
      'request'=>jwt,
      'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      'client_assertion' => get_private_key_jwt(@client_private_key_jwt,"RS256", @priv_key_rsa, @certificate_rsa)
      }, {}
    # p last_response
    assert last_response.created?
    uri = (JSON.parse last_response.body)['request_uri']
    # GET /authorize
    get  ('/authorize?request_uri='+uri+'&client_id='+@client_private_key_jwt.client_id), {}, {}
    assert last_response.redirect?
    assert ["http://localhost:4567/consent", "http://localhost:4567/login"].include? last_response.original_headers['Location']
  end
end
