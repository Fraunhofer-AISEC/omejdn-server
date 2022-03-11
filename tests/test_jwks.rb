# frozen_string_literal: true
require 'test/unit'
require 'rack/test'
require_relative 'config_testsetup'
require_relative '../omejdn'

class JWKSTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    TestSetup.setup
  end

  def teardown
    TestSetup.teardown
  end

  def test_jwks
    get '/jwks.json'
    assert last_response.ok?
    jwks = JSON.parse last_response.body
    assert_equal 1, jwks.length
    assert jwk = jwks['keys'].select{|k| k[:kid] = 'jexs4cfi5p3NUziLELGwTV7r9gZsLcTBnFp-m4vu0aw'}.first
    assert_equal "RSA", jwk['kty']
    assert_equal "sig", jwk['use']
    assert_equal 2, jwk['x5c'].length
    assert jwk['x5t']
  end
end
