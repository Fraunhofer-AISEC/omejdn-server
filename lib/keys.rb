# frozen_string_literal: true

require 'openssl'
require 'jwt'
KEYS_TARGET_OMEJDN = 'omejdn'
KEYS_TARGET_CLIENT = 'clients'

# Key and Certificate Management
class Keys
  # Stores a cryptographic key (pk or sk) and/or certificates
  def self.store_key(target_type, target, key_material)
    PluginLoader.fire('KEYS_STORE', binding)
  end

  # Loads a cryptographic key (sk where available) and/or certificates
  def self.load_key(target_type, target, create_key: false)
    key_material = PluginLoader.fire('KEYS_LOAD', binding).first
    if key_material['sk'].nil? && create_key
      (key_material = {})['sk'] = OpenSSL::PKey::RSA.new 2048
      key_material['pk'] = key_material['sk'].public_key
      store_key(target_type, target, key_material)
    end
    key_material['kid'] = JWT::JWK.new(key_material['pk']).export[:kid] if key_material['pk']
    key_material.compact
  end

  # Loads all available keys and certificates for a target_type
  # May contain duplicates and expired certificates
  def self.load_all_keys(target_type)
    PluginLoader.fire('KEYS_LOAD_ALL', binding).flatten
  end

  def self.gen_x5c(certs)
    certs.map { |cert| Base64.strict_encode64(cert.to_der).strip }
  end

  def self.gen_x5t(certs)
    Base64.urlsafe_encode64(OpenSSL::Digest::SHA1.new(certs[0].to_der).to_s)
  end

  def self.generate_jwks
    { keys: (load_all_keys(KEYS_TARGET_OMEJDN).map do |k|
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

# The default Keys DB stores keys and certificates as PEM in /keys
class DefaultKeysDB
  KEYS_DIR = 'keys'

  def self.store_key(bind)
    target_type  = bind.local_variable_get :target_type
    target       = bind.local_variable_get :target
    key_material = bind.local_variable_get :key_material
    filename = "#{KEYS_DIR}/#{target_type}/#{target}"

    # Ensure the directory exists
    if (key_material['certs'] || key_material['sk']) && !(File.directory? "#{KEYS_DIR}/#{target_type}")
      Dir.mkdir "#{KEYS_DIR}/#{target_type}"
    end

    # Certificates
    if key_material['certs'].nil?
      FileUtils.rm_rf "#{filename}.cert"
    else
      pem = key_material['certs'].map(&:to_pem).join("\n")
      File.write("#{filename}.cert", pem)
    end

    # Keys
    if key_material['sk'].nil?
      FileUtils.rm_rf "#{filename}.key"
    else
      File.write("#{filename}.key", key_material['sk'])
    end
  end

  def self.load_key(bind)
    target_type = bind.local_variable_get :target_type
    target      = bind.local_variable_get :target
    result = {}
    filename = "#{KEYS_DIR}/#{target_type}/#{target}"

    # Try to load keys
    if File.exist?("#{filename}.key")
      begin
        key = OpenSSL::PKey::RSA.new File.read("#{filename}.key")
        result['sk'] = key if key.private?
        result['pk'] = key.private? ? key.public_key : key
      rescue StandardError
        p 'Loading key failed'
      end
    end

    # Try to load certificate (chain)
    if File.exist?("#{filename}.cert")
      begin
        certs = OpenSSL::X509::Certificate.load_file("#{filename}.cert")
        raise 'Certificate expired' if certs[0].not_after < Time.now
        raise 'Certificate not yet valid' if certs[0].not_before > Time.now

        result['certs'] = certs if result['sk'].nil? || (certs[0].check_private_key result['sk'])
      rescue StandardError
        p 'Loading certificate failed'
      end
    end
    result
  end

  def self.load_all_keys(bind)
    target_type = bind.local_variable_get :target_type
    return [] unless File.directory? "#{KEYS_DIR}/#{target_type}"

    Dir.entries("#{KEYS_DIR}/#{target_type}").reject { |f| f.start_with? '.' }.map do |f|
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

  # register functions
  def self.register
    PluginLoader.register 'KEYS_STORE',    method(:store_key)
    PluginLoader.register 'KEYS_LOAD',     method(:load_key)
    PluginLoader.register 'KEYS_LOAD_ALL', method(:load_all_keys)
  end
end
