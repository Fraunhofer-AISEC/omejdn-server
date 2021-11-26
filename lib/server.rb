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

  def self.setup_cert(key, token_type, filename)
    p "WARNING: Creating a self-signed dummy certificate at #{filename}."
    p "         Use this only for testing purposes."
    p "         To discourage active use, the certificate is only valid for two days."
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(2**512)
    cert.subject = OpenSSL::X509::Name.parse "/DC=org/DC=example/CN=Omejdn CA"
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = cert.not_before + 3600 * 24 * 2 # Now + 2 days
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
    cert.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign, digitalSignature", true))
    cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
    cert.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    file = File.new filename, File::CREAT | File::TRUNC | File::RDWR
    file.write(cert.to_pem)
    file.close
    config = Config.base_config
    config[token_type]['certificates'] ||= []
    config[token_type]['certificates'] << filename
    Config.base_config = config
    cert
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
    cert = load_certs(token_type).select{|c| c.check_private_key sk}.first
    cert = setup_cert(sk,token_type,filename+".cert") if cert.nil?
    { 'sk'=>sk, 'cert'=>cert}
  end
end
