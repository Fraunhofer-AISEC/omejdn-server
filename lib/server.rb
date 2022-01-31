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
    (pk || {}).merge({ 'sk' => sk, 'pk' => sk.public_key })
  end
end
