# frozen_string_literal: true
require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative 'config_testsetup'
require_relative '../omejdn'
require_relative '../lib/token_helper'
require_relative '../lib/verifiable_credentials'

class OAuth2Test < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    TestSetup.setup
    @client = Client.find_by_id 'testClient'
    @token = TokenHelper.build_access_token @client, [], TestSetup.config['host'], nil, {}
  end

  def teardown
    TestSetup.teardown
  end

  def test_verifiable_credentials
    get '/vc', {'claims'=>{'email'=>{'value' => 'test@example.org'}}}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    jwt = JWT.decode(last_response.body, Server.load_key('verifiable_credentials').public_key, true, { algorithm: TestSetup.config['token']['algorithm'] })
    (JSON.pretty_generate jwt).split("\n").each{|l| p l}
  end

end
