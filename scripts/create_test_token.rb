# frozen_string_literal: true

require 'openssl'
require 'jwt'
require 'json'

##
# NOTE:
# The client_id in config/clients.yml must match the 'iss' and 'sub' claim
# of the JWT you generate.
# Do not forget to configure the 'certfile' of your client so that
# omejdn can find you public key which corrsponds to the private key you
# use to sign this JWT.
#
# The 'aud' claim MUST correspond to the HOST environment parameter
# or the 'host' value in the config/omejdn.yml.
# Alternatively, if omejdn is started with the OMEJDN_JWT_AUD_OVERRIDE
# environment variable you must use that value instead.
#

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
