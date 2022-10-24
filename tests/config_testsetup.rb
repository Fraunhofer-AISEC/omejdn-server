# frozen_string_literal: true

# We want to intercept any storage request Omejdn makes,
# so we do not actually overwrite any data.
# To do this, we first edit ENV so Omejdn loads our custom plugins file,
# which disables writing to disk.
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
    (json = @config[section]&.to_json) ? JSON.parse(json) : nil # Simple deep copy
  end

  def self.store_key(bind)
    target_type = bind.local_variable_get :target_type
    target      = bind.local_variable_get :target
    jwks        = bind.local_variable_get :jwks
    (@keys[target_type] ||= {})[target] = jwks
  end

  def self.load_key(bind)
    target_type = bind.local_variable_get :target_type
    target      = bind.local_variable_get :target
    create_key  = bind.local_variable_get :create_key
    (json = @keys.dig(target_type, target)&.to_json) ? JSON.parse(json) : JWT::JWK::Set.new.export # Simple deep copy
  end

  def self.load_all_keys(bind)
    target_type = bind.local_variable_get :target_type
    result = JWT::JWK::Set.new
    (@keys[target_type] || {}).values.map do |jwks|
      new_jwks = (json = jwks&.to_json) ? JSON.parse(json) : JWT::JWK::Set.new.export # Simple deep copy
      result.merge(JWT::JWK::Set.new(new_jwks))
    end
    result.export
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
      'attributes' => {
        'omejdn' => 'write',
        'openid' => true,
        'profile' => true,
        'email' => 'admin@example.com',
        'asdfasf' => 'asdfasf',
        'exampleKey' => 'exampleValue'
      },
      'password' => '$2a$12$s1UhO7bRO9b5fTTiRE4KxOR88vz3462Bxn8DGh/iDX26Neh95AHrC', # "mypassword"
      'backend' => 'yaml'
    },
    {
      'username' => 'testUser2',
      'attributes' => {
        'omejdn' => 'write'
      },
      'password' => '$2a$12$Be9.8qVsGOVpUFO4ebiMBel/TNetkPhnUkJ8KENHjHLiDG.IXi0Zi',
      'backend' => 'yaml'
    },
    {
      'username' => 'dynamic_claims',
      'attributes' => {
        'omejdn' => 'write',
        'dynattribute' => {
          'dynamic' => true
        }
      },
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
      'attributes' => {'omejdn' => 'write'}
     },{
      'client_id' => 'client_secret_post_client',
      'client_secret' => 'post_secret',
      'token_endpoint_auth_method' => 'client_secret_post',
      'grant_types' => ['authorization_code','client_credentials'],
      'scope' => ['omejdn:write', 'openid', 'email'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => {'omejdn' => 'write'}
     },{
      'client_id' => 'private_key_jwt_client',
      'token_endpoint_auth_method' => 'private_key_jwt',
      'grant_types' => ['authorization_code','client_credentials'],
      'scope' => ['omejdn:write', 'openid', 'email'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => {'omejdn' => 'write'}
     },{
      'client_id' => 'publicClient',
      'token_endpoint_auth_method' => 'none',
      'grant_types' => ['authorization_code','client_credentials'],
      'scope' => ['omejdn:write'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => {'omejdn' => 'write'}
     },{
      'client_id' => 'resourceClient',
      'token_endpoint_auth_method' => 'none',
      'grant_types' => ['authorization_code','client_credentials'],
      'scope' => ['omejdn:write'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => {'omejdn' => 'write'},
      'resource' => ['http://example.org','http://localhost:4567/api']
     },{
      'client_id' => 'dynamic_claims',
      'token_endpoint_auth_method' => 'none',
      'grant_types' => ['authorization_code','client_credentials'],
      'client_name' => 'omejdn admin ui',
      'scope' => ['omejdn:write'],
      'redirect_uris' => 'http://localhost:4200',
      'attributes' => {
        'dynattribute' => {
          'dynamic' => true
        },
        'omejdn' => 'write'
      }
    }]#.map { |c| Client.from_h(c) }
  end
end
