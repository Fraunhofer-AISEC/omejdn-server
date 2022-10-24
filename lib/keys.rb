# frozen_string_literal: true

require 'openssl'
require 'jwt'
KEYS_TARGET_OMEJDN = 'omejdn'

# JWKS Management
class Keys
  def self.store_keys(target_type, target, jwks)
    jwks = jwks.export(include_private: true)
    PluginLoader.fire('KEYS_STORE', binding)
  end

  def self.load_keys(target_type, target, create_key: false)
    jwks = JWT::JWK::Set.new(PluginLoader.fire('KEYS_LOAD', binding).first)
    if jwks.none? && create_key
      jwks = JWT::JWK::Set.new(JWT::JWK.new(OpenSSL::PKey::RSA.new(2048), use: 'sig', alg: 'RS256'))
      store_keys(target_type, target, jwks)
    end
    jwks
  end

  def self.load_all_keys(target_type)
    JWT::JWK::Set.new(PluginLoader.fire('KEYS_LOAD_ALL', binding).first)
  end

  def self.ensure_usability(jwk)
    # NOTE: No support for x5u and key_ops atm.
    # Certificates may overwrite a lot of defaults, so we handle them first
    certs = jwk[:x5c]&.map { |c| OpenSSL::X509::Certificate.new(Base64.strict_decode64(c)) }
    if certs
      # Ensure the first certificate contains the correct key
      return unless jwk.kid == JWT::JWK.new(certs[0].public_key).kid

      # Check current validity (just by time)
      return if certs[0].not_after < Time.now
      return if certs[0].not_before > Time.now

      # Set Thumbprints
      jwk[:x5t]        = Base64.urlsafe_encode64(OpenSSL::Digest.new('SHA1',   certs[0].to_der).to_s)
      jwk[:'x5t#S256'] = Base64.urlsafe_encode64(OpenSSL::Digest.new('SHA256', certs[0].to_der).to_s)

      # Check usage restrictions
      usages = certs[0].extensions&.find { |ext| ext.oid == 'keyUsage' }&.value&.split("\n")&.map do |usage|
        # C.t. RFC 5280, Section 4.2.1.3
        # We do not care about encipherOnly and decipherOnly for the `use` param
        if ['Digital Signature', 'Non Repudiation', 'Content Commitment', 'Key Cert Sign', 'CRL Sign'].include? usage
          'sig'
        elsif ['Key Encipherment', 'Data Encipherment', 'Key Agreement'].include? usage
          'enc'
        end
      end

      usages.compact!.uniq!
      return if jwk[:use] && !usages.include?(jwk[:use])

      jwk[:use] = usages[0] if usages.length == 1
    end

    jwk[:use] ||= 'sig' # By default, every key is a signature key
    jwk[:alg] ||= default_alg jwk
  end

  def self.default_alg(jwk)
    case jwk[:use]
    when 'sig'
      case jwk
      when JWT::JWK::RSA
        'RS256'
      when JWT::JWK::EC
        'ES256'
      end
    when 'enc'
      'none' # We only support signing
    end
  end
end

# The default Keys DB stores keys and certificates as PEM in /keys
class DefaultKeysDB
  KEYS_DIR = 'keys'

  def self.store_keys(bind)
    target_type = bind.local_variable_get :target_type
    target      = bind.local_variable_get :target
    jwks        = bind.local_variable_get :jwks

    # Create directory and delete existing key material
    Dir.mkdir "#{KEYS_DIR}/#{target_type}" unless File.directory? "#{KEYS_DIR}/#{target_type}"
    FileUtils.rm Dir.glob("#{KEYS_DIR}/#{target_type}/#{target}.*")

    JWT::JWK::Set.new(jwks).each do |jwk|
      key_params = JWT::JWK.new(jwk.keypair).export.keys
      desc_params = jwk.export.except(*key_params)
      file_prefix = "#{KEYS_DIR}/#{target_type}/#{target}.#{desc_params.delete(:kid)}"

      # Save optional x509 certificate chain to file as PEM
      if (certs = desc_params.delete(:x5c))
        certs = certs.map { |c| OpenSSL::X509::Certificate.new(Base64.strict_decode64(c)).to_pem }
        File.write("#{file_prefix}.cert", certs.join("\n"))
        # TODO: delete other x5* data from desc_params
      end

      # Save remaining desc_params to file as YAML
      File.write("#{file_prefix}.yml", desc_params.to_yaml)

      # If no x509 cert or private key available, save key to file as PEM
      if jwk.private?
        File.write("#{file_prefix}.key", jwk.keypair.to_pem)
      elsif cert_chain.nil?
        File.write("#{file_prefix}.key", jwk.public_key.to_pem)
      end
    end
  end

  def self.load_keys(bind, target = nil)
    target_type = bind.local_variable_get :target_type

    # Find relevant key file groups
    target_glob = "#{KEYS_DIR}/#{target_type}/"
    target_glob += "#{target}." if target
    keys = Dir.glob("#{target_glob}*").group_by do |f|
      name_parts = f.split('/').last.split('.')
      name_parts.pop # file ending
      name_parts.join('.')
    end

    # Read files and assemble JWKs
    keys.map! do |_, filenames|
      desc_params = {}
      key = nil

      filenames.each do |f|
        case f.split('.').last
        when 'key'
          key = OpenSSL::PKey.read(File.read(f)) # Only OpenSSL algos supported atm
        when 'cert'
          certs = OpenSSL::X509::Certificate.load_file f
          desc_params[:x5c] = certs.map { |c| Base64.strict_encode64 c.to_der }
          key ||= certs[0]&.public_key
          # TODO: Add other x5* data to desc_params
        when 'yml'
          desc_params.merge!(YAML.safe_load(File.read(f)), filename: f)
        end
      end

      JWT::JWK.new key, desc_params if key
    end

    { keys: keys }
  end

  def self.load_target_keys(bind)
    target = bind.local_variable_get :target
    load_keys bind, target
  end

  # register functions
  def self.register
    PluginLoader.register 'KEYS_STORE',    method(:store_key)
    PluginLoader.register 'KEYS_LOAD',     method(:load_target_keys)
    PluginLoader.register 'KEYS_LOAD_ALL', method(:load_keys)
  end
end
