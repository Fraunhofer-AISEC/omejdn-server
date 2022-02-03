# frozen_string_literal: true

# Always load this BEFORE omejdn.rb

require 'yaml'

class TestSetup

  def self.backup
    @backup_users   = File.read './config/users.yml'
    @backup_clients = File.read './config/clients.yml'
    @backup_omejdn  = File.read './config/omejdn.yml'
    File.open('./config/users.yml', 'w')   { |file| file.write(users.to_yaml) }
    File.open('./config/clients.yml', 'w') { |file| file.write(clients.to_yaml) }
    File.open('./config/omejdn.yml', 'w')  { |file| file.write(config.to_yaml) }
  end

  def self.setup
    File.open('./config/users.yml', 'w')   { |file| file.write(users.to_yaml) }
    File.open('./config/clients.yml', 'w') { |file| file.write(clients.to_yaml) }
    File.open('./config/omejdn.yml', 'w')  { |file| file.write(config.to_yaml) }
  end

  def self.teardown
    File.open('./config/users.yml', 'w')   { |file| file.write(@backup_users) }
    File.open('./config/clients.yml', 'w') { |file| file.write(@backup_clients) }
    File.open('./config/omejdn.yml', 'w')  { |file| file.write(@backup_omejdn) }
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
    }]
  end

  def self.clients
    [{
      'client_id' => 'testClient',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write', 'openid', 'email'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => []
    },
     {
       'client_id' => 'testClient2',
       'name' => 'omejdn admin ui',
       'allowed_scopes' => ['omejdn:write'],
       'redirect_uri' => 'http://localhost:4200',
       'attributes' => [],
       'allowed_resources' => ['http://example.org','http://localhost:4567/api']
     },{
      'client_id' => 'dynamic_claims',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => [
        { 'key' => 'dynattribute', 'dynamic' => true }
      ]
    }]
  end

  def self.config
    {
      'host' => 'http://localhost:4567',
      'bind_to' => '0.0.0.0',
      'path_prefix' => '',
      'app_env' => 'test',
      'openid' => true,
      'token' => {
        'expiration' => 3600,
        'signing_key' => 'tests/test_resources/omejdn_test.pem',
        'jwks_additions' => [
          'tests/test_resources/omejdn_test.cert'
        ],
        'algorithm' => 'RS256',
        'audience' => 'TestServer',
        'issuer' => 'http://localhost:4567'
      },
      'id_token' => {
        'expiration' => 3600,
        'signing_key' => 'tests/test_resources/omejdn_test.pem',
        'jwks_additions' => [
          'tests/test_resources/omejdn_test.cert'
        ],
        'algorithm' => 'RS256',
        'issuer' => 'http://localhost:4567'
      },
      'plugins' => {
        'user_db' => {
          'yaml' => {
            'location' => 'config/users.yml'
          }
        },
        'api' => {
          'admin_v1' => nil,
          'user_selfservice_v1' => {
            'allow_deletion' => true,
            'allow_password_change' => true,
            'editable_attributes' => ['name']
          }
        },
        'claim_mapper' => {
          'attribute' => nil
        }
      },
      'user_backend_default' => 'yaml'
    }
  end
end

# Backup all Config Files
TestSetup.backup