# frozen_string_literal: true

# Always load this BEFORE omejdn.rb

require 'yaml'

class TestSetup

  def self.backup
    @backup_clients = File.read './config/clients.yml' rescue nil
    @backup_omejdn  = File.read './config/omejdn.yml'  rescue nil
    File.open('./config/users_test.yml', 'w')   { |file| file.write(users.to_yaml) }
    File.open('./config/clients.yml', 'w') { |file| file.write(clients.to_yaml) }
    File.open('./config/omejdn.yml', 'w')  { |file| file.write(config.to_yaml) }
  end

  def self.setup
    File.open('./keys/omejdn/omejdn_test.cert', 'w') do |file|
      file.write (File.read './tests/test_resources/omejdn_test.cert')
    end
    File.open('./config/users_test.yml', 'w')   { |file| file.write(users.to_yaml) }
    File.open('./config/clients.yml', 'w') { |file| file.write(clients.to_yaml) }
    File.open('./config/omejdn.yml', 'w')  { |file| file.write(config.to_yaml) }
  end

  def self.teardown
    File.delete './config/users_test.yml'
    File.delete './keys/omejdn/omejdn_test.cert'
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
    }]
  end

  def self.config
    {
      'issuer' => 'http://localhost:4567',
      'front_url' => 'http://localhost:4567',
      'bind_to' => '0.0.0.0:4567',
      'environment' => 'test',
      'openid' => true,
      'default_audience' => 'TestServer',
      'accept_audience' => 'http://localhost:4567',
      'user_backend_default' => 'yaml',
      'access_token' => {
        'expiration' => 3600,
        'algorithm' => 'RS256',
      },
      'id_token' => {
        'expiration' => 3600,
        'algorithm' => 'RS256',
      },
      'plugins' => {
        'user_db' => {
          'yaml' => {
            'location' => 'config/users_test.yml'
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
      }
    }
  end
end

# Backup all Config Files
TestSetup.backup