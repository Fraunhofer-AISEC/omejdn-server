ENV['APP_ENV'] = 'test'

require 'test/unit'
require 'rack/test'
require 'webrick/https'
require 'fileutils'
require 'jwt'
require 'openssl'
require_relative '../omejdn'
require_relative '../lib/token_helper'

class AlgsTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    # Load private keys
    @priv_key_ec256 = OpenSSL::PKey::EC.new File.read './tests/test_resources/ec256.pem'
    @priv_key_ec512 = OpenSSL::PKey::EC.new File.read './tests/test_resources/ec512.pem'
    @priv_key_rsa = OpenSSL::PKey::RSA.new File.read './tests/test_resources/rsa.pem'

    # Setup certificates in keys directory for the server to check the JWTs
    FileUtils.cp('./tests/test_resources/ec256.cert', './keys/ZWMyNTY=.cert')
    FileUtils.cp('./tests/test_resources/ec512.cert', './keys/ZWM1MTI=.cert')
    FileUtils.cp('./tests/test_resources/rsa.cert', './keys/cnNh.cert')

    # Backup information in the server to restore when done testing
    @backup_users   = File.read './config/users.yml'
    @backup_clients = File.read './config/clients.yml'
    @backup_omejdn  = File.read './config/omejdn.yml'
    File.open('./config/users.yml', 'w')   { |file| file.write(users_testsetup.to_yaml) }
    File.open('./config/clients.yml', 'w') { |file| file.write(clients_testsetup.to_yaml) }
    File.open('./config/omejdn.yml', 'w')  { |file| file.write(config_testsetup.to_yaml) }
  end

  def teardown
    # Restore information from backup
    File.open('./config/users.yml', 'w')   { |file| file.write(@backup_users) }
    File.open('./config/clients.yml', 'w') { |file| file.write(@backup_clients) }
    File.open('./config/omejdn.yml', 'w')  { |file| file.write(@backup_omejdn) }
    
    # Delete testing certs from server
    File.open('./keys/ZWMyNTY=.cert', 'w')   { |file| File.delete(file) }
    File.open('./keys/ZWM1MTI=.cert', 'w')   { |file| File.delete(file) }
    File.open('./keys/cnNh.cert', 'w')   { |file| File.delete(file) }
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
      'password' => "$2a$12$Be9.8qVsGOVpUFO4ebiMBel/TNetkPhnUkJ8KENHjHLiDG.IXi0Zi"
    }]
  end

  def clients_testsetup
    [{
      'client_id' => 'ec256',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => [],
      'certfile' => 'ec256.cert'
    },
    {
      'client_id' => 'ec512',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => [],
      'certfile' => 'ec512.cert'
    },
    {
      'client_id' => 'rsa',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:write'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => [],
      'certfile' => 'rsa.cert'
    }]
  end

  def config_testsetup
    {
      'host' => 'http://localhost:4567',
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
      'user_backend' => [ 'yaml' ]
    }
  end

  def generate_token(alg, iss)
    base_config = Config.base_config
    now = Time.new.to_i
    payload = { aud: base_config['token']['issuer'],
              sub: iss,
              iss: iss,
              iat: now,
              nbf: now,
              exp: now + 3600
              }
    if alg == "ES256"
      jwt = JWT.encode payload, @priv_key_ec256, 'ES256'
    elsif alg == "ES512"
      jwt = JWT.encode payload, @priv_key_ec512, 'ES512'
    elsif alg == "RS256"
      jwt = JWT.encode payload, @priv_key_rsa, 'RS256'
    elsif alg == "RS512"
      jwt = JWT.encode payload, @priv_key_rsa, 'RS512'
    elsif alg == "PS256"
      jwt = JWT.encode payload, @priv_key_rsa, 'PS256'
    elsif alg == "PS512"
      jwt = JWT.encode payload, @priv_key_rsa, 'PS512'
    end
  end

  def test_es256
    jwt = generate_token "ES256", "ec256"
    post '/token', {
        'grant_type' => 'client_credentials',
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => jwt,
        'scope' => 'omejdn:write'
         }, {}
    assert last_response.ok?
  end

  def test_es512
    jwt = generate_token "ES512", "ec512"
    post '/token', {
        'grant_type' => 'client_credentials',
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => jwt,
        'scope' => 'omejdn:write'
         }, {}
    assert last_response.ok?
  end

  def test_rs512
    jwt = generate_token "RS512", "rsa"
    post '/token', {
        'grant_type' => 'client_credentials',
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => jwt,
        'scope' => 'omejdn:write'
         }, {}
    assert last_response.ok?
  end

  def test_rs256
    jwt = generate_token "RS256", "rsa"
    post '/token', {
        'grant_type' => 'client_credentials',
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => jwt,
        'scope' => 'omejdn:write'
         }, {}
    assert last_response.ok?
  end

  def test_ps512
    jwt = generate_token "PS512", "rsa"
    post '/token', {
        'grant_type' => 'client_credentials',
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => jwt,
        'scope' => 'omejdn:write'
         }, {}
    assert last_response.bad_request?
  end

  def test_ps256
    jwt = generate_token "PS256", "rsa"
    post '/token', {
        'grant_type' => 'client_credentials',
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => jwt,
        'scope' => 'omejdn:write'
         }, {}
      assert last_response.bad_request?
  end
end
