# frozen_string_literal: true

require_relative './config'
require 'openssl'

# Server setup helper functions.
class Server
  def self.setup_key(filename)
    rsa_key = OpenSSL::PKey::RSA.new 2048
    file = File.new filename, File::CREAT | File::TRUNC | File::RDWR
    file.write(rsa_key.to_pem)
    file.close
    p "Created new key at #{filename}"
  end

  def self.load_certs(token_type = 'token')
    config = Config.base_config
    cert_files = config.dig(token_type, 'certificates') || []
    cert_files.filter { |f| File.exist? f }.map { |f| OpenSSL::X509::Certificate.new File.read(f) }
  end

  # Taken from https://stackoverflow.com/questions/50657463/how-to-obtain-value-of-x5t-using-certificate-credentials-for-application-authe
  def self.gen_x5t(cert)
    Base64.encode64(OpenSSL::Digest::SHA1.new(cert.to_der).to_s.upcase.scan(/../).map(&:hex).pack('c*')).strip
  end

  def self.load_key(token_type = 'token')
    filename = Config.base_config[token_type]['signing_key']
    setup_key(filename) unless File.exist? filename
    sk = OpenSSL::PKey::RSA.new File.read(filename)
    cert = load_certs.select{|c| c.check_private_key sk}.first
    { 'sk'=>sk, 'cert'=>cert}
  end
end
