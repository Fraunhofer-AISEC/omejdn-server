# frozen_string_literal: true

ENV['APP_ENV'] = 'test'

require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative '../omejdn'
require_relative '../lib/token_helper'

class ApiTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    client = Client.find_by_id 'testClient'
    @token = TokenHelper.build_access_token client, ['omejdn:api', 'omejdn:admin'], nil
  end

  def teardown
    File.open('./config/users.yml', 'w') { |file| file.write(users_to_yaml) }
    File.open('./config/clients.yml', 'w') { |file| file.write(clients_to_yaml) }
    File.open('./config/omejdn.yml', 'w') { |file| file.write(config_to_yaml) }
  end

  def users_to_yaml
    users = [{
      'username' => 'testUser',
      'scopes' => ['omejdn:api', 'openid', 'profile'],
      'attributes' => [
        { 'key' => 'email', 'value' => 'admin@example.com' },
        { 'key' => 'asdfasf', 'value' => 'asdfasf' },
        { 'key' => 'exampleKey', 'value' => 'exampleValue' }
      ],
      'password' => "$2a$12$Be9.8qVsGOVpUFO4ebiMBel/TNetkPhnUkJ8KENHjHLiDG.IXi0Zi"
    }]
    users.to_yaml
  end

  def clients_to_yaml
    clients = [{
      'client_id' => 'testClient',
      'name' => 'omejdn admin ui',
      'allowed_scopes' => ['omejdn:api'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => []
    },
               {
                 'client_id' => 'testClient2',
                 'name' => 'omejdn admin ui',
                 'allowed_scopes' => ['omejdn:api'],
                 'redirect_uri' => 'http://localhost:4200',
                 'attributes' => []
               }]
    clients.to_yaml
  end

  def config_to_yaml
    config = {
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
        'expiration' => 360_000,
        'signing_key' => 'omejdn_priv.pem',
        'algorithm' => 'RS256',
        'issuer' => 'http://localhost:4567'
      },
      'user_backend' => [ 'yaml' ]
    }
    config.to_yaml
  end

  def test_get_users
    get '/api/v1/config/users', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    #p last_response
    assert last_response.ok?
    assert_equal '[{"username":"testUser",'\
    '"scopes":["omejdn:api","openid","profile"],'\
    '"attributes":[{"key":"email","value":"admin@example.com"},'\
    '{"key":"asdfasf","value":"asdfasf"},'\
    '{"key":"exampleKey","value":"exampleValue"}],'\
    '"password":"$2a$12$Be9.8qVsGOVpUFO4ebiMBel/TNetkPhnUkJ8KENHjHLiDG.IXi0Zi"}]', last_response.body
  end

  def test_get_user
    get '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    #p last_response
    assert last_response.ok?
    assert_equal '{"username":"testUser",'\
    '"scopes":["omejdn:api","openid","profile"],'\
    '"attributes":[{"key":"email","value":"admin@example.com"},'\
    '{"key":"asdfasf","value":"asdfasf"},{"key":"exampleKey",'\
    '"value":"exampleValue"}],"password":"$2a$12$Be9.8qVsGOVpUFO4ebiMBel/TNetkPhnUkJ8KENHjHLiDG.IXi0Zi"}', last_response.body
  end

  def test_post_user
    user = {
      'username' => 'testUser2',
      'attributes' => [
        { 'key' => 'exampleKey2', 'value' => 'exampleValue2' }
      ],
      'password' => "somepw",
      'userBackend' => "yaml",
      'extern' => nil
    }
    post '/api/v1/config/users/testUser2', user.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    user.delete('userBackend')
    #p last_response
    assert last_response.created?
    get '/api/v1/config/users/testUser2', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    #p last_response
    assert last_response.ok?
    new_user = JSON.parse(last_response.body)
    new_user.delete('password') # This will be a salted string
    user.delete('password')
    assert_equal user, new_user
  end

  def test_put_user
    user = {
      'username' => 'testUser',
      'attributes' => [
        { 'key' => 'exampleKey', 'value' => 'exampleValue2' }
      ],
      'password' => "secure",
      'extern' => nil
    }
    put '/api/v1/config/users/testUser', user.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    new_user = JSON.parse(last_response.body)
    user.delete('password')
    new_user.delete('password')
    assert last_response.ok?
    assert_equal user, new_user
  end

  def test_delete_user
    delete '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    #p last_response
    assert last_response.no_content?
    get '/api/v1/config/users/testUser', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert_equal '', last_response.body
  end

  def test_get_clients
    get '/api/v1/config/clients', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    clients = [{
        "client_id" => "testClient",
        "name" => "omejdn admin ui",
        "allowed_scopes" => ["omejdn:api"],
        "redirect_uri" => "http://localhost:4200",
        "attributes" => []
      },{
        "allowed_scopes" => ["omejdn:api"],
        "name" => "omejdn admin ui",
        "client_id" => "testClient2",
        "redirect_uri" => "http://localhost:4200",
        "attributes" => []
    }]
    assert last_response.ok?
    assert_equal clients, JSON.parse(last_response.body)
  end

  def test_get_client
    get '/api/v1/config/clients/testClient', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    clnt = {
      "client_id" => "testClient",
      "name" => "omejdn admin ui",
      "allowed_scopes" => ["omejdn:api"],
      "redirect_uri" => "http://localhost:4200",
      "attributes" => []
    }
    assert_equal clnt, JSON.parse(last_response.body)
  end

  def test_put_client
    client = {
      'client_id' => 'testClient2',
      'name' => 'omejdn admin ui',
      'certfile' => nil,
      'allowed_scopes' => ['omejdn:api'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => []
    }
    put '/api/v1/config/clients/testClient2', client.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    get '/api/v1/config/clients/testClient2', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal client, JSON.parse(last_response.body)
  end

  def test_post_client
    client = {
      'client_id' => 'testClient3',
      'name' => 'omejdn admin ui',
      'certfile' => nil,
      'allowed_scopes' => ['omejdn:api'],
      'redirect_uri' => 'http://localhost:4200',
      'attributes' => []
    }
    post '/api/v1/config/clients/testClient3', client.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?
    get '/api/v1/config/clients/testClient3', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal client, JSON.parse(last_response.body)
  end

  def test_delete_client
    delete '/api/v1/config/clients/testClient', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/clients/testClient', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert_equal '', last_response.body
  end

  def test_get_config
    get '/api/v1/config/omejdn', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal '{"host":"http://localhost:4567","openid":true,'\
    '"token":{"expiration":3600,"signing_key":"omejdn_priv.pem",'\
    '"algorithm":"RS256","audience":"TestServer",'\
    '"issuer":"http://localhost:4567"},'\
    '"id_token":{"expiration":360000,"signing_key":"omejdn_priv.pem",'\
    '"algorithm":"RS256","issuer":"http://localhost:4567"},"user_backend":["yaml"]}', last_response.body
  end

  def test_put_config
    config = {
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
      }
    }
    put '/api/v1/config/omejdn', config.to_json, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.no_content?
    get '/api/v1/config/omejdn', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal '{"host":"http://localhost:4567","openid":true,'\
    '"token":{"expiration":3600,"signing_key":"omejdn_priv.pem",'\
    '"algorithm":"RS256","audience":"TestServer",'\
    '"issuer":"http://localhost:4567"},'\
    '"id_token":{"expiration":3600,"signing_key":"omejdn_priv.pem",'\
    '"algorithm":"RS256","issuer":"http://localhost:4567"}}', last_response.body
  end

  def test_certificate_03_put
    cert = {
      'certfile' => "#{Base64.urlsafe_encode64('testClient')}.cert",
      'certificate' => "-----BEGIN CERTIFICATE-----
MIICQzCCAaygAwIBAgIBATANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAt0ZXN0
Q2xpZW50MjAeFw0yMDAzMTgxNzQzMzVaFw0yMTAzMTgxNzQzMzVaMBYxFDASBgNV
BAMMC3Rlc3RDbGllbnQyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRymVJ
kS2owmHhxmJ9HJkBHhu+X2AsCuBmNJnt/00PJH5sW/MU6gQrpKTDR/GQzNzE71wL
F3oXEY8hxoGcmElj5n8WtITXR86pifaMIFkknqMYHLE0CEejt92zkhCzqTARkRAf
xH+atGZpSDAPd3KhdoRbnP3+QWz/Xx/Sb68F7QIDAQABo4GgMIGdMAkGA1UdEwQC
MAAwCwYDVR0PBAQDAgUgMB0GA1UdDgQWBBQO291LYnF0VVCEdUPAkQLyONaSdDAT
BgNVHSUEDDAKBggrBgEFBQcDATAPBglghkgBhvhCAQ0EAhYAMD4GA1UdIwQ3MDWA
FA7b3UticXRVUIR1Q8CRAvI41pJ0oRqkGDAWMRQwEgYDVQQDDAt0ZXN0Q2xpZW50
MoIBATANBgkqhkiG9w0BAQsFAAOBgQAfts/lpn7kknjtZ4AcKxdCloBBdGLRGEaW
b/x55UrJ8Ghso3MdpKB48IG0cBu+cGD9isNu77SKEqzPzJx+wnceJOt5GSaNNXYw
/Y34Uo7+pNxj7Nn5h5rLgNgfcFh5FeeBQ+RE+7nO2O+JFptheis9mcSLOJxElXYN
+i6yol5y8Q==
-----END CERTIFICATE-----\n"
    }
    put '/api/v1/config/clients/keys/testClient', cert.to_json,
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    get '/api/v1/config/clients/keys/testClient', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal cert, JSON.parse(last_response.body)
    cert = {
      'certificate' => "-----BEGIN CERTIFICATE-----
MIICQzCCAaygAwIBAgIBATANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAt0ZXN0
Q2xpZW50MjAeFw0yMDAzMTgxNzQzMzdaFw0yMTAzMTgxNzQzMzdaMBYxFDASBgNV
BAMMC3Rlc3RDbGllbnQyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTO7ov
BQ0FvgNIDIloz3uPKHe7XBiDerYwX+S+L1sWIUXvcKpY/igs0gqmNOWTknkrrVKW
l62iPGOhrTsig+jOkHX5mmj8P0Y+bf0zMIWceX4S0d6O2ZC1lv08Be/CX/jGSUmU
FRWSvGo+TKPQqWn/4Bf28DduVw2p6z917H30LwIDAQABo4GgMIGdMAkGA1UdEwQC
MAAwCwYDVR0PBAQDAgUgMB0GA1UdDgQWBBRk8oaobfGpvv6kOd3Yw31YHV2jrDAT
BgNVHSUEDDAKBggrBgEFBQcDATAPBglghkgBhvhCAQ0EAhYAMD4GA1UdIwQ3MDWA
FGTyhqht8am+/qQ53djDfVgdXaOsoRqkGDAWMRQwEgYDVQQDDAt0ZXN0Q2xpZW50
MoIBATANBgkqhkiG9w0BAQsFAAOBgQCo2oYpH/MzunB4eP7Mwek9UrRcXp10rL4D
PExqY4rJ43CWpPOjIWAxCLRic/x3P0K19ukZk9GHNdQerUvyAJiubo8iH366kXfu
9+XBMDtJ5tvhwn0nTylTTaWnSu47O/o9DWfzlGoYfLV1jTrvwUcozymVWprnmeCs
3WF1B0RcEQ==
-----END CERTIFICATE-----"
    }
    put '/api/v1/config/clients/keys/testClient', cert.to_json,
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
  end

  def test_certificate_00_post
    cert = {
      'certfile' => "#{Base64.urlsafe_encode64('testClient2')}.cert",
      'certificate' => "-----BEGIN CERTIFICATE-----
MIICQzCCAaygAwIBAgIBATANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAt0ZXN0
Q2xpZW50MjAeFw0yMDAzMTgxOTEyNDJaFw0yMTAzMTgxOTEyNDJaMBYxFDASBgNV
BAMMC3Rlc3RDbGllbnQyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+XtuO
xb5heLPf63qFIcT9PEkz9mnTOZeO2laSWVgKLB9lZLEliz/jT+0utG9ae5gHaJvQ
CAE+54nO3PQYn5aHpjQxCHr4S0Bd5TmZIVNB3dZs3TgBcmp1zmqzE8x/sgzTCYwW
SpD/8Fz0DHGWaRSDLS3e1wqohpgyc+FoL7WWtQIDAQABo4GgMIGdMAkGA1UdEwQC
MAAwCwYDVR0PBAQDAgUgMB0GA1UdDgQWBBSeVx082PpdfjOwDppX1+WG9krGXzAT
BgNVHSUEDDAKBggrBgEFBQcDATAPBglghkgBhvhCAQ0EAhYAMD4GA1UdIwQ3MDWA
FJ5XHTzY+l1+M7AOmlfX5Yb2SsZfoRqkGDAWMRQwEgYDVQQDDAt0ZXN0Q2xpZW50
MoIBATANBgkqhkiG9w0BAQsFAAOBgQA3dZXiU7/iamW0b+6fnhdz5myG/xgMdsTh
RVi07KVPe2LvGoNr+jy8pxiOXXOE/lJ0NyDtQS1hJTemmATitFm1ct6JyII+uCke
jGwgRDStkayeDGynlH+ROAqyERyMa22pLlYAXdhIKgs6MnUOPhPZbM6ewfqT670W
xBcEdFWvuA==
-----END CERTIFICATE-----\n"
    }
    post '/api/v1/config/clients/keys/testClient2', cert.to_json,
         { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.created?
    get '/api/v1/config/clients/keys/testClient2', {},
        { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    assert_equal cert, JSON.parse(last_response.body)
    File.delete('./keys/' + "#{Base64.urlsafe_encode64('testClient2')}.cert")
  end
end
