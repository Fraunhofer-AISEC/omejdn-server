#!/usr/bin/env ruby
# frozen_string_literal: true

require 'openssl'
require 'jwt'
require 'json'

def error(msg)
  print "#{msg}\n"
  exit
end

if ARGV.length < 2 || ARGV.length > 3
  error "Usage: create_test_token.rb client_id keyfile (AUD)\n" \
        "\n" \
        "NOTE: The client_id must be specified in `config/clients.yml`.\n" \
        "A certificate for the client must be registered. If in doubt,\n" \
        "use the `import_certfile` option in `config/clients.yml` to\n" \
        "import it. The AUD value must correspond to the value set by\n" \
        "Omejdn. If you overwrote it, you must specify the correct\n" \
        'value here. This script only supports RSA keys.'
end

client_id = ARGV[0]
keyfile = ARGV[1]
aud = ENV['HOST'] || 'http://localhost:4567'
aud = ARGV[2] if ARGV.length >= 3

error 'ERROR: File not existent.' unless File.exist? keyfile
key = OpenSSL::PKey::RSA.new File.read(keyfile)

payload = {
  'iss' => client_id,
  'sub' => client_id,
  'exp' => Time.new.to_i + 3600,
  'nbf' => Time.new.to_i,
  'iat' => Time.new.to_i,
  'aud' => aud
}
token = JWT.encode payload, key, 'RS256'
puts token
