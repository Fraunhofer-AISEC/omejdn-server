# frozen_string_literal: true

require 'openssl'
require 'jwt'
require 'json'

def load_key
  if File.exist? 'keys/testClient.key'
    filename = 'keys/testClient.key'
    rsa_key = OpenSSL::PKey::RSA.new File.read(filename)
  else
    rsa_key = OpenSSL::PKey::RSA.new 2048
    pfile = File.new 'keys/testClient.key', File::CREAT | File::TRUNC | File::RDWR
    pfile.write(rsa_key.to_pem)
    pfile.close
  end
  rsa_key
end

# Only for debugging!
client_rsa_key = load_key
payload = { 'iss' => 'testClient', 'sub' => 'testClient', 'exp' => Time.new.to_i + 3600, 'nbf' => Time.new.to_i,
            'iat' => Time.new.to_i, 'aud' => 'https://api.localhost' }
token = JWT.encode payload, client_rsa_key, 'RS256'
puts token
