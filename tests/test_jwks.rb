# frozen_string_literal: true
require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative 'config_testsetup'
require_relative '../omejdn'
require_relative '../lib/token_helper'

class JWKSTest < Test::Unit::TestCase
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

  def test_jwks
    get '/.well-known/jwks.json'
    assert last_response.ok?
    jwks = JSON.parse last_response.body
    assert_equal 1, jwks.length
    jwk = jwks[0]
    assert_equal "RSA", jwk['kty']
    assert_equal "sig", jwk['use']
    assert_equal 2, jwk['x5c'].length
    assert jwk['x5t']
  end
end
