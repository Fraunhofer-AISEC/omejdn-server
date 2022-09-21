# frozen_string_literal: true

require_relative 'id_credential'

# Cache for nonces
class NonceCache
  class << self; attr_accessor :acceptable_nonces end
  @acceptable_nonces = {} # Mapping from client_ids to nonces

  def self.get_nonce(client_id)
    nonce = SecureRandom.uuid
    (@acceptable_nonces[client_id] ||= []) << nonce
    nonce
  end

  def self.verify_nonce(client_id, nonce)
    @acceptable_nonces[client_id]&.delete(nonce)
  end
end

# Credential issuance endpoint
endpoint '/credential_issuance', ['POST'], public_endpoint: true do
  token  = Token.decode env.fetch('HTTP_AUTHORIZATION', '')&.slice(7..-1), nil
  client = Client.find_by_id token['client_id']
  user   = User.find_by_id   token['sub']
  json   = JSON.parse request.body.read
  raise 'no_user_or_client' unless user && client
  raise 'no_type_specified' unless json['type']
  # Determine using the scopes whether a credential may be issued
  raise 'insufficient_scope' unless token['scope'].split.include? "credential:#{json['type']}"

  # Optionally verify PoP
  if json['proof']
    id = verify_identifier json['proof'], client
    raise 'unaccepted_proof' unless id
  end

  # Build credential
  credential = build_credential json['type'], json['format'], user, id
  raise 'issuing_failed' unless credential&.dig('format') && credential&.dig('credential')

  halt 200, { 'Content-Type' => 'application/json' }, credential.to_json
rescue StandardError => e
  p e if debug
  c_nonce = NonceCache.get_nonce client.client_id if client
  halt 400, { 'Content-Type' => 'application/json' }, {
    error: e.to_s,
    c_nonce: c_nonce,
    c_nonce_expires_in: 86_400
  }.compact.to_json
end

# Verifies control over a cryptographic secret, whose public counterpart may be
# resolvable from an identifier (e.g. DID) or included in the proof (e.g. JWT).
# Consumes a nonce
def verify_identifier(pop, client)
  return unless pop&.dig('proof_type')

  case pop['proof_type']
  when 'jwt'
    verify_options = {
      algorithms: %w[RS256 RS512 ES256 ES512],
      verify_iat: true,
      iss: client.client_id,
      verify_iss: true,
      aud: Config.base_config['issuer'],
      verify_aud: true
    }
    body, header = JWT.decode pop['jwt'], nil, true, verify_options do |header, _body|
      # We only support JWKs atm. TODO: Support for x5c
      JWT::JWK.import(header['jwk']).keypair.public_key
    end
    # check nonce
    return unless NonceCache.verify_nonce client.client_id, body['nonce']

    jwk_thumbprint header['jwk']
  end
end

# Temporary helper, until JWT can do this for us properly
def jwk_thumbprint(jwk)
  jwk = jwk.clone
  jwk.delete(:kid)
  digest = Digest::SHA256.new
  digest << jwk.sort.to_h.to_json
  digest.base64digest.gsub('+', '-').gsub('/', '_').gsub('=', '')
end

# Calls other plugins to build a credential
def build_credential(type, format, subject, subject_id)
  (PluginLoader.fire "PLUGIN_CREDENTIAL_ISSUANCE_BUILD_#{type.upcase}", binding).compact.first
end

# Adds the necessary data to the metadata
# Credentials are defined by other plugins
def add_to_metadata(bind)
  metadata = bind.local_variable_get :metadata
  metadata['credential_endpoint'] = "#{Config.base_config['front_url']}/credential_issuance"
  credentials_supported = {}
  PluginLoader.fire 'PLUGIN_CREDENTIAL_ISSUANCE_LIST', binding
  metadata['credentials_supported'] = credentials_supported
end
PluginLoader.register 'STATIC_METADATA', method(:add_to_metadata)
