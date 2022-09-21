# frozen_string_literal: true

def simple_credential_map_attributes(conf, subject)
  credential_subject = {}
  conf['mapping']&.each do |m|
    return if m['required'] && !subject.claim?(m['attribute'])

    subject.attributes.each do |a|
      next unless a['key'] == m['attribute']

      path = m['target'].split('/')
      current = credential_subject
      current = (current[path.shift] ||= {}) while path.length > 1
      current[path.shift] = a['value']
    end
  end
  credential_subject
end

def build_simple_credential(bind)
  type       = bind.local_variable_get :type
  req_format = bind.local_variable_get :format
  subject    = bind.local_variable_get :subject
  subject_id = bind.local_variable_get :subject_id

  conf = PluginLoader.configuration('credential_issuance')&.dig('simple_credentials', type)
  return unless conf

  # Optionally require binding to an identifier
  return if conf['binding'] && subject_id.nil?

  # We only support `vc_jwt` for simple_credentials
  return unless req_format == 'jwt_vc'

  # Check prerequisites with subject and fill in values
  return unless (credential_subject = simple_credential_map_attributes(conf, subject))

  # Assemble the JWT-VC
  base_config = Config.base_config
  now = Time.new.to_i
  jwt_body = {
    'iss' => base_config['issuer'],
    'sub' => subject_id,
    'jti' => SecureRandom.uuid,
    'nbf' => now,
    'iat' => now,
    'exp' => now + (3600 * 24 * 365),
    'nonce' => SecureRandom.uuid,
    'vc' => {
      '@context' => conf['context'],
      'type' => conf['types'],
      'credentialSubject' => credential_subject
    }.compact
  }
  key_pair = Keys.load_key KEYS_TARGET_OMEJDN, 'omejdn', create_key: true
  credential = JWT.encode jwt_body, key_pair['sk'], 'RS256', { typ: 'at+jwt', kid: key_pair['kid'] }
  { 'format' => 'jwt_vc', 'credential' => credential }
end

# Register plugin handler for each simple credential type
PluginLoader.configuration('credential_issuance')&.dig('simple_credentials')&.each do |id, _|
  PluginLoader.register "PLUGIN_CREDENTIAL_ISSUANCE_BUILD_#{id.upcase}", method(:build_simple_credential)
end

def id_credential_metadata(bind)
  credentials = bind.local_variable_get :credentials_supported

  conf = PluginLoader.configuration('credential_issuance')&.dig('simple_credentials')
  return unless conf

  conf.each do |id, data|
    credentials[id] = {
      display: data['display'],
      formats: {
        'jwt_vc' => {
          'types' => data['types']
        }
      }
    }
    next unless data['binding']

    credentials.dig(id, :formats, 'jwt_vc').merge!({
                                                     'cryptographic_binding_methods_supported' => ['jwk'],
                                                     'cryptographic_suites_supported' => %w[RS256 RS512 ES256 ES512]
                                                   })
  end
end
PluginLoader.register 'PLUGIN_CREDENTIAL_ISSUANCE_LIST', method(:id_credential_metadata)
