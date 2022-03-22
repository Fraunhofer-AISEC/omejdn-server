# frozen_string_literal: true

require_relative './config'
require 'openssl'
require 'jwt'

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

  def self.load_pkey
    Dir.entries('keys/omejdn').reject { |f| f.start_with? '.' }.map do |f|
      result = {}
      # The file could be either a certificate or a key
      begin
        result['certs'] = OpenSSL::X509::Certificate.load_file "keys/omejdn/#{f}"
        result['pk'] = result['certs'][0].public_key
      rescue StandardError
        key = OpenSSL::PKey::RSA.new File.read("keys/omejdn/#{f}")
        result['pk'] = key.public_key
      end
      result
    end
  end

  def self.load_skey
    filename = 'keys/omejdn/omejdn.key'
    setup_skey(filename) unless File.exist? filename
    sk = OpenSSL::PKey::RSA.new File.read(filename)
    pk = load_pkey.select { |c| c.dig('certs', 0) && (c.dig('certs', 0).check_private_key sk) }.first
    kid = JWT::JWK.new(sk.public_key).export[:kid]
    (pk || {}).merge({ 'sk' => sk, 'pk' => sk.public_key, 'kid' => kid })
  end

  def self.generate_jwks
    { keys: (load_pkey.map do |k|
      jwk = JWT::JWK.new(k['pk']).export
      jwk[:use] = 'sig'
      if k['certs']
        jwk[:x5c] = gen_x5c(k['certs'])
        jwk[:x5t] = gen_x5t(k['certs'])
      end
      jwk
    end).uniq { |k| k[:kid] } }
  end
end
