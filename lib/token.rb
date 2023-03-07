# frozen_string_literal: true

require_relative './keys'
require_relative './config'
require_relative './client'

# A helper for building JWT access tokens and ID tokens
class Token
  # Builds a RFC 9068 JWT access token for client including scopes and attributes
  def self.access_token(client, user, scopes, claims, resources)
    # Use user attributes if we have a user context, else use client
    # attributes.
    base_config = Config.base_config
    now = Time.new.to_i
    token = {
      'scope' => (scopes.join ' '),
      'aud' => resources,
      'iss' => base_config['issuer'],
      'sub' => user&.username || client.client_id,
      'nbf' => now,
      'iat' => now,
      'jti' => SecureRandom.uuid,
      'exp' => now + base_config.dig('access_token', 'expiration'),
      'client_id' => client.client_id
    }
    PluginLoader.fire 'TOKEN_CREATED_ACCESS_TOKEN', binding
    reserved = {}
    reserved['userinfo_req_claims'] = claims['userinfo'] unless (claims['userinfo'] || {}).empty?
    token['omejdn_reserved'] = reserved unless reserved.empty?
    jwks = Keys.load_keys(KEYS_TARGET_OMEJDN, 'omejdn', create: true)
    key = jwks.find { |k| k[:use] == 'sig' && k.private? }
    JWT.encode token, key.keypair, key[:alg], { typ: 'at+jwt', kid: key[:kid] }
  end

  # Builds a JWT ID token for client including user attributes
  def self.id_token(client, user, scopes, claims, nonce)
    base_config = Config.base_config
    now = Time.new.to_i
    token = {
      'aud' => client.client_id,
      'iss' => base_config['issuer'],
      'sub' => user.username,
      'nbf' => now,
      'iat' => now,
      'exp' => now + base_config.dig('id_token', 'expiration'),
      'auth_time' => user.auth_time,
      'nonce' => nonce
    }.compact
    PluginLoader.fire 'TOKEN_CREATED_ID_TOKEN', binding
    jwks = Keys.load_keys KEYS_TARGET_OMEJDN, 'omejdn', create: true
    key = jwks.find { |k| k[:use] == 'sig' && k.private? }
    JWT.encode token, key.keypair, key[:alg], { typ: 'JWT', kid: key[:kid] }
  end

  # Decodes an access token or id token for inspection
  def self.decode(token, endpoint = nil)
    raise 'No token found' if token.nil? | token.empty?

    jwks = Keys.load_all_keys(KEYS_TARGET_OMEJDN)
    jwks.select! { |k| k[:use] == 'sig' }
    args = { algorithms: jwks.keys.map { |k| k[:alg] }.uniq, jwks: jwks }
    args.merge!({ aud: "#{Config.base_config['front_url']}#{endpoint}", verify_aud: true }) if endpoint
    JWT.decode(token, nil, true, args)[0]
  end
end
