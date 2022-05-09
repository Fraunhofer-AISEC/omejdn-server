# frozen_string_literal: true
require 'test/unit'
require 'rack/test'
require_relative 'config_testsetup'
require_relative '../omejdn'
require_relative '../lib/token'

class OpenIDTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    TestSetup.setup(config: { 'openid' => true } )

    @client = Client.find_by_id 'publicClient'
    @user   = User.find_by_id 'testUser'
    @token  = Token.access_token @client, nil, ['openid'], {}, TestSetup.config['front_url']+"/api"
  end

  def test_pkce
    OAuthHelper.validate_pkce('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                                     'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', 'S256')
  end

  def test_jwks
    get '/jwks.json'
    assert last_response.ok?
    jwks = JSON.parse last_response.body
    assert_equal 1, jwks.length
    assert jwk = jwks['keys'].select{|k| k[:kid] = 'jexs4cfi5p3NUziLELGwTV7r9gZsLcTBnFp-m4vu0aw'}.first
    assert_equal "RSA", jwk['kty']
    assert_equal "sig", jwk['use']
    # This check is currently not reliable.
    # TODO: Better test setup to copy all keys and certs to the correct positions
    # assert_equal 2, jwk['x5c'].length
    # assert jwk['x5t']
  end

end