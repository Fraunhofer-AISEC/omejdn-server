# frozen_string_literal: true

require_relative './config'
require 'openssl'

# Key and Certificate Management
class Keys
  def self.setup_skey(filename)
    rsa_key = OpenSSL::PKey::RSA.new 2048
    file = File.new filename, File::CREAT | File::TRUNC | File::RDWR
    file.write(rsa_key.to_pem)
    file.close
    p "Created new key at #{filename}"
  end

  def self.gen_x5c(certs)
    certs.map { |cert| Base64.encode64(cert.to_der).strip }
  end

  def self.gen_x5t(certs)
    Base64.urlsafe_encode64(OpenSSL::Digest::SHA1.new(certs[0].to_der).to_s)
  end

  def self.load_pkey(token_type = 'token')
    cert_files = Config.base_config.dig(token_type, 'jwks_additions') || []
    cert_files.filter { |f| File.exist? f }.map do |f|
      result = {}
      # The file could be either a certificate or a key
      begin
        result['certs'] = OpenSSL::X509::Certificate.load_file f
        result['pk'] = result['certs'][0].public_key
      rescue StandardError
        key = OpenSSL::PKey::RSA.new File.read(f)
        result['pk'] = key.public_key
      end
      result
    end
  end

  def self.load_skey(token_type = 'token')
    filename = Config.base_config.dig(token_type, 'signing_key')
    setup_skey(filename) unless File.exist? filename
    sk = OpenSSL::PKey::RSA.new File.read(filename)
    pk = load_pkey(token_type).select { |c| c.dig('certs', 0) && (c.dig('certs', 0).check_private_key sk) }.first
    kid = JSON::JWK.new(sk.public_key)[:kid]
    (pk || {}).merge({ 'sk' => sk, 'pk' => sk.public_key, 'kid' => kid })
  end

  def self.generate_jwks
    jwks = JSON::JWK::Set.new
    %w[token id_token].each do |type|
      # Load the signing key
      key_material = [load_skey(type)]
      key_material += load_pkey(type)
      key_material.each do |k|
        # Internally, this creates a KID following RFC 7638 using SHA256
        # Only works with RSA, EC-Keys, and symmetric keys though.
        # Further key types will require upstream changes
        jwk = JSON::JWK.new(k['pk'])
        jwk[:use] = 'sig'
        if k['certs']
          jwk[:x5c] = gen_x5c(k['certs'])
          jwk[:x5t] = gen_x5t(k['certs'])
        end
        jwks << jwk
      end
    end
    { keys: jwks.uniq { |k| k['kid'] } }
  end
end
