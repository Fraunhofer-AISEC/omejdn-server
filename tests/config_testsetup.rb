# frozen_string_literal: true

# We want to intercept any storage request Omejdn makes,
# so we do not actually overwrite any data.
# To do this, we first edit ENV,
# so Omejdn loads our custom plugins file.
# Tests may add additional plugins
plugin_files = ENV['OMEJDN_PLUGINS']&.split(':') || []
plugin_files << 'tests/test_resources/setup.yml'
ENV.clear # Fresh ENV
ENV['OMEJDN_PLUGINS'] = plugin_files.join(':')

# Next we write our own handler for storage requests,
# which simply saves any data in this class
require_relative '../lib/plugins'
class TestDB
  class << self; attr_accessor :config, :keys end
  @config = {} # The Config DB
  @keys = {} # The Keys DB

  def self.write_config(bind)
    section = bind.local_variable_get :section
    data    = bind.local_variable_get :data
    @config[section] = data
  end

  def self.read_config(bind)
    section  = bind.local_variable_get :section
    fallback = bind.local_variable_get :fallback
    JSON.parse((@config[section] || fallback).to_json) # Simple deep copy
  end

  def self.store_key(bind)
    target_type  = bind.local_variable_get :target_type
    target       = bind.local_variable_get :target
    key_material = bind.local_variable_get :key_material
    raise 'ERROR' if key_material['pk'].nil? && key_material.keys.length.positive?
    (@keys[target_type] ||= {})[target] = key_material
  end

  def self.load_key(bind)
    target_type = bind.local_variable_get :target_type
    target      = bind.local_variable_get :target
    create_key  = bind.local_variable_get :create_key
    @keys.dig(target_type, target) || {}
  end

  def self.load_all_keys(bind)
    target_type = bind.local_variable_get :target_type
    (@keys[target_type] || {}).values
  end

  PluginLoader.register 'CONFIGURATION_STORE', method(:write_config)
  PluginLoader.register 'CONFIGURATION_LOAD',  method(:read_config)
  PluginLoader.register 'KEYS_STORE',          method(:store_key)
  PluginLoader.register 'KEYS_LOAD',           method(:load_key)
  PluginLoader.register 'KEYS_LOAD_ALL',       method(:load_all_keys)
end

# Finally we load Omejdn
require_relative '../omejdn'

# Omejdn should be initialized with its default configuration now,
# so you can use the core functionality to store data.
# Alternatively, e.g. if that functionality is what you are testing,
# you can also just access TestDB.config and TestDB.keys directly.

# For convenience, a few functions to help with setting up the configuration
# These do not depend on Omejdn and edit the TestDB directly
# Call them inside setup and teardown
class TestSetup
  def self.setup(config: {}, clients: [], users: [])
    TestDB.config['omejdn'].merge!(config)
    TestDB.config['clients'] = TestSetup.clients
    TestDB.config['users'] = TestSetup.users
  end

  def self.users
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
      'password' => '$2a$12$s1UhO7bRO9b5fTTiRE4KxOR88vz3462Bxn8DGh/iDX26Neh95AHrC', # "mypassword"
      'backend' => 'yaml'
    },
    {
      'username' => 'testUser2',
      'attributes' => [
        { 'key' => 'omejdn', 'value' => 'write' }
      ],
      'password' => '$2a$12$Be9.8qVsGOVpUFO4ebiMBel/TNetkPhnUkJ8KENHjHLiDG.IXi0Zi',
      'backend' => 'yaml'
    },
    {
      'username' => 'dynamic_claims',
      'attributes' => [
        { 'key' => 'omejdn', 'value' => 'write' },
        { 'key' => 'dynattribute', 'dynamic' => true }
      ],
      'password' => '$2a$12$s1UhO7bRO9b5fTTiRE4KxOR88vz3462Bxn8DGh/iDX26Neh95AHrC',
      'backend' => 'yaml'
    }]#.map { |u| User.from_h(u) }
  end

  def self.clients
    [{
      'client_id' => 'client_secret_basic_client',
      'client_secret' => 'basic_secret',
      'token_endpoint_auth_method' => 'client_secret_basic',
      'grant_types' => ['authorization_code','client_credentials'],
      'scope' => ['omejdn:write', 'openid', 'email'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => [{'key'=> 'omejdn', 'value'=> 'write'}]
     },{
      'client_id' => 'client_secret_post_client',
      'client_secret' => 'post_secret',
      'token_endpoint_auth_method' => 'client_secret_post',
      'grant_types' => ['authorization_code','client_credentials'],
      'scope' => ['omejdn:write', 'openid', 'email'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => [{'key'=> 'omejdn', 'value'=> 'write'}]
     },{
      'client_id' => 'private_key_jwt_client',
      'token_endpoint_auth_method' => 'private_key_jwt',
      'grant_types' => ['authorization_code','client_credentials'],
      'scope' => ['omejdn:write', 'openid', 'email'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => [{'key'=> 'omejdn', 'value'=> 'write'}]
     },{
      'client_id' => 'publicClient',
      'token_endpoint_auth_method' => 'none',
      'grant_types' => ['authorization_code','client_credentials'],
      'scope' => ['omejdn:write'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => [{'key'=> 'omejdn', 'value'=> 'write'}]
     },{
      'client_id' => 'resourceClient',
      'token_endpoint_auth_method' => 'none',
      'grant_types' => ['authorization_code','client_credentials'],
      'scope' => ['omejdn:write'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => [{'key'=> 'omejdn', 'value'=> 'write'}],
      'resource' => ['http://example.org','http://localhost:4567/api']
     },{
      'client_id' => 'dynamic_claims',
      'token_endpoint_auth_method' => 'none',
      'grant_types' => ['authorization_code','client_credentials'],
      'client_name' => 'omejdn admin ui',
      'scope' => ['omejdn:write'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => [
        { 'key' => 'dynattribute', 'dynamic' => true },
        {'key'=> 'omejdn', 'value'=> 'write'}
      ]
    }]#.map { |c| Client.from_h(c) }
  end

  def self.config
    {
      'issuer' => 'http://localhost:4567',
      'front_url' => 'http://localhost:4567',
      'bind_to' => '0.0.0.0:4567',
      'environment' => 'test',
      'openid' => false,
      'default_audience' => [],
      'accept_audience' => 'http://localhost:4567',
      'user_backend_default' => 'yaml',
      'access_token' => {
        'expiration' => 3600,
        'algorithm' => 'RS256',
      },
      'id_token' => {
        'expiration' => 3600,
        'algorithm' => 'RS256',
      }
    }
    TestDB.config['omejdn']
  end
end
