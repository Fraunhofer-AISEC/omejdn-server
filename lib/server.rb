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
    # FIXME: The chain is supposed to be represented via an array of certificates
    certs.map { |cert| Base64.encode64(cert.to_der).strip }
  end

  def self.gen_x5t(certs)
    Base64.urlsafe_encode64(OpenSSL::Digest::SHA1.new(certs[0].to_der).to_s)
  end

  def self.load_pkey(token_type = 'token')
    config = Config.base_config
    cert_files = config.dig(token_type, 'jwks_additions') || []
    cert_files.filter { |f| File.exist? f }.map do |f|
      file_contents = File.read(f)
      result = {}
      # The file could be either a certificate or a key
      begin
        # Is it a cert/-chain?
        # FIXME: The OpenSSL Ruby Gem will eventually get support for chain loading starting with version 3.0.0
        # See: https://github.com/ruby/openssl/pull/441
        # For now, we support PEM chains using this hack
        if file_contents.ascii_only? # PEM with chain support
          chain_split = file_contents.split('-----')
          chain = chain_split.select.with_index do |_, i|
            ((i - 2) % 4).zero?
          end
          chain = chain.map { |c| "-----BEGIN CERTIFICATE-----\n#{c}-----END CERTIFICATE-----\n" }
        else # DER
          chain = [file_contents]
        end
        certs = chain.map { |c| OpenSSL::X509::Certificate._load c }
        result['certs'] = certs
        result['pk'] = certs[0].public_key
      rescue StandardError
        # Is it a secret/public key?
        key = OpenSSL::PKey :RSA.new file_contents
        result['pk'] = key.public_key
      end
      result
    end
  end

  def self.load_skey(token_type = 'token')
    filename = Config.base_config[token_type]['signing_key']
    setup_skey(filename) unless File.exist? filename
    sk = OpenSSL::PKey::RSA.new File.read(filename)
    pk = load_pkey(token_type).select { |c| c.dig('certs', 0) && (c['certs'][0].check_private_key sk) }.first
    (pk || {}).merge({ 'sk' => sk, 'pk' => sk.public_key })
  end
end
