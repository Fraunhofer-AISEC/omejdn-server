# frozen_string_literal: true

ENV['APP_ENV'] = 'test'

require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative '../omejdn'
require_relative '../lib/token_helper'

class SelfsServiceApiTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    user = User.find_by_id 'testUser'
    client = Client.find_by_id 'testClient'
    @write_token = TokenHelper.build_access_token client, ['omejdn:write'], user
    @read_token = TokenHelper.build_access_token client, ['omejdn:read'], user
    @useless_token = TokenHelper.build_access_token client, [], user

    @backup_users   = File.read './config/users.yml'
    File.open('./config/users.yml', 'w')   { |file| file.write(users_testsetup.to_yaml) }
  end

  def teardown
    File.open('./config/users.yml', 'w')   { |file| file.write(@backup_users) }
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
      'password' => "$2a$12$s1UhO7bRO9b5fTTiRE4KxOR88vz3462Bxn8DGh/iDX26Neh95AHrC" # "mypassword"
    },
    {
      'username' => 'testUser2',
      'attributes' => [
        { 'key' => 'omejdn', 'value' => 'write' },
      ],
      'password' => "$2a$12$Be9.8qVsGOVpUFO4ebiMBel/TNetkPhnUkJ8KENHjHLiDG.IXi0Zi"
    }]
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
    expected = users_testsetup[0]
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
