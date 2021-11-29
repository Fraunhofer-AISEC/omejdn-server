# frozen_string_literal: true

require_relative './config'
require 'openssl'

# Server setup helper functions.
class Server
  def self.setup_skey(filename)
    rsa_key = OpenSSL::PKey::RSA.new 2048
    file = File.new filename, File::CREAT | File::TRUNC | File::RDWR
    file.write(rsa_key.to_pem)
    file.close
    p "Created new key at #{filename}"
  end

  def self.gen_x5c(cert)
    # FIXME: The chain is supposed to be represented via an array of certificates
    [Base64.encode64(cert.to_der).strip]
  end

  def self.gen_x5t(cert)
    Base64.urlsafe_encode64(OpenSSL::Digest::SHA1.new(cert.to_der).to_s)
  end

  # We derive KIDs from the PK hashes
  def self.gen_kid(public_key)
    Base64.urlsafe_encode64(OpenSSL::Digest::SHA1.new(public_key.to_der).to_s)
  end

  def self.load_pkey(token_type = 'token')
    config = Config.base_config
    cert_files = config.dig(token_type, 'jwks_additions') || []
    cert_files.filter { |f| File.exist? f }.map do |f|
      file_contents = File.read(f)
      result = {}
      # The file could be either a certificate or a key
      begin
        # Is it a cert?
        cert = OpenSSL::X509::Certificate.new file_contents
        result['cert'] = cert
        result['pk'] = cert.public_key
      rescue StandardError => e
        # Is it a secret/public key?
        key = OpenSSL::PKey:RSA.new file_contents
        result['pk'] = key.public_key
      end
      result
    end
  end

  def self.load_skey(token_type = 'token')
    filename = Config.base_config[token_type]['signing_key']
    setup_skey(filename) unless File.exist? filename
    sk = OpenSSL::PKey::RSA.new File.read(filename)
    pk = load_pkey(token_type).select { |c| c['cert'] && (c['cert'].check_private_key sk) }.first
    (pk || {}).merge({ 'sk' => sk, 'pk' => sk.public_key })
  end
end
