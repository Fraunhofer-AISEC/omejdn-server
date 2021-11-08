# frozen_string_literal: true

# Always load this BEFORE omejdn.rb
ENV['OMEJDN_IGNORE_ENV'] = "true"


class TestSetup

  def self.setup
    @backup_users   = File.read './config/users.yml'
    @backup_clients = File.read './config/clients.yml'
    @backup_omejdn  = File.read './config/omejdn.yml'
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
      'password' => '$2a$12$s1UhO7bRO9b5fTTiRE4KxOR88vz3462Bxn8DGh/iDX26Neh95AHrC' # "mypassword"
    },
    {
      'username' => 'testUser2',
      'attributes' => [
        { 'key' => 'omejdn', 'value' => 'write' }
      ],
      'password' => '$2a$12$Be9.8qVsGOVpUFO4ebiMBel/TNetkPhnUkJ8KENHjHLiDG.IXi0Zi'
    },
    {
      'username' => 'dynamic_claims',
      'attributes' => [
        { 'key' => 'omejdn', 'value' => 'write' },
        { 'key' => 'dynattribute', 'dynamic' => true }
      ],
      'password' => '$2a$12$s1UhO7bRO9b5fTTiRE4KxOR88vz3462Bxn8DGh/iDX26Neh95AHrC'
    }]
  end

  def self.clients
    [{
      'client_id' => 'testClient',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => [
        'key' =>'email',
        'value' => 'test@example.org'
      ]
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
        'signing_key' => 'omejdn_priv.pem',
        'algorithm' => 'RS256',
        'audience' => 'TestServer',
        'issuer' => 'http://localhost:4567'
      },
      'id_token' => {
        'expiration' => 3600,
        'signing_key' => 'omejdn_priv.pem',
        'algorithm' => 'RS256',
        'issuer' => 'http://localhost:4567'
      },
      'verifiable_credentials' => {
        'enabled' => true,
        'expiration' => 3600,
        'signing_key' => 'omejdn_priv.pem',
        'algorithm' => 'RS256',
        'issuer' => 'http://localhost:4567'
      },
      'user_backend' => ['yaml'],
      'user_backend_default' => 'yaml',
      'user_selfservice' => {
        'enabled' => true,
        'allow_deletion' => true,
        'allow_password_change' => true,
        'editable_attributes' => ['name']
      }
    }
  end
end
