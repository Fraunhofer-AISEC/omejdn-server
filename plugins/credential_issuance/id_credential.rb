# frozen_string_literal: true

def build_id_credential(bind)
  req_format = bind.local_variable_get :format
  subject    = bind.local_variable_get :subject
  subject_id = bind.local_variable_get :subject_id

  # Require binding to an identifier
  return unless subject_id

  # We only support `vc_jwt`
  return unless req_format == 'jwt_vc'

  # Our ID Credential consists of a Name and birth date,
  # and we only issue the credential if we have at least the following
  return unless (subject.claim? 'given_name') && (subject.claim? 'family_name') && (subject.claim? 'birthdate')

  credential_subject = { name: {} }
  subject.attributes.each do |a|
    credential_subject[:name][a['key']] = a['value'] if %w[given_name middle_name family_name].include? a['key']
    credential_subject[a['key']] = a['value'] if a['key'] == 'birthdate'
  end

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
      '@context' => ['https://www.w3.org/2018/credentials/v1'],
      'type' => %w[VerifiableCredential IDCredential],
      'credentialSubject' => credential_subject
    }
  }
  key_pair = Keys.load_key KEYS_TARGET_OMEJDN, 'omejdn', create_key: true
  credential = JWT.encode jwt_body, key_pair['sk'], 'RS256', { typ: 'at+jwt', kid: key_pair['kid'] }
  { 'format' => 'jwt_vc', 'credential' => credential }
end
PluginLoader.register 'PLUGIN_CREDENTIAL_ISSUANCE_BUILD_ID_CREDENTIAL', method(:build_id_credential)

def id_credential_metadata(bind)
  credentials = bind.local_variable_get :credentials_supported
  credentials['id_credential'] = {
    display: {
      name: 'ID Credential'
    },
    formats: {
      'jwt_vc' => {
        'types' => %w[VerifiableCredential IDCredential],
        'cryptographic_binding_methods_supported' => ['jwk'],
        'cryptographic_suites_supported' => %w[RS256 RS512 ES256 ES512]
      }
    }
  }
end
PluginLoader.register 'PLUGIN_CREDENTIAL_ISSUANCE_LIST', method(:id_credential_metadata)
