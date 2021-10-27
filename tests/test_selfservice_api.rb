# frozen_string_literal: true

ENV['APP_ENV'] = 'test'

require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative '../omejdn'
require_relative '../lib/token_helper'
require_relative 'config_testsetup'

class SelfServiceApiTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    TestSetup.setup
    user = User.find_by_id 'testUser'
    client = Client.find_by_id 'testClient'
    @write_token = TokenHelper.build_access_token client, ['omejdn:write'], TestSetup.config['host']+"/api", user
    @read_token = TokenHelper.build_access_token client, ['omejdn:read'], TestSetup.config['host']+"/api", user
    @useless_token = TokenHelper.build_access_token client, [], TestSetup.config['host']+"/api", user
  end

  def teardown
    TestSetup.teardown
  end

  def test_require_read_scope
    get '/api/v1/user', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@useless_token}" }
    assert last_response.forbidden?
  end

  def test_require_write_scope
    payload = {
      'attributes' => [
        { 'key' => 'omejdn', 'value' => 'write' }
      ]
    }
    put '/api/v1/user', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@useless_token}" }
    assert last_response.forbidden?
    put '/api/v1/user', payload.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@read_token}" }
    assert last_response.forbidden?
  end

  def test_get
    get '/api/v1/user', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@read_token}" }
    assert last_response.ok?
    expected = TestSetup.users[0]
    expected.delete('password')
    assert_equal expected, JSON.parse(last_response.body)
  end

  def test_put
    payload = {
      'attributes' => [
        { 'key' => 'name', 'value' => 'Dieter' }
      ]
    }
    put '/api/v1/user', payload.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@write_token}" }
    assert last_response.no_content?
    get '/api/v1/user', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@write_token}" }
    assert last_response.ok?
    assert_equal payload['attributes'], JSON.parse(last_response.body)['attributes']
  end

  def test_update_password
    payload = {
      'currentPassword' => 'mypassword',
      'newPassword' => 'mynewpassword'
    }
    put '/api/v1/user/password', payload.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@write_token}" }
    assert last_response.no_content?
    put '/api/v1/user/password', payload.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@write_token}" }
    assert last_response.forbidden?
    # TODO: Check the change using e.g. the admin API
  end

  def test_get_provider
    get '/api/v1/user/provider', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@write_token}" }
    assert last_response.not_found?
    # TODO: Add an actual example here
  end

  def test_delete
    delete '/api/v1/user', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@write_token}" }
    assert last_response.no_content?
    get '/api/v1/user', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@write_token}" }
    assert last_response.unauthorized?
  end
end
