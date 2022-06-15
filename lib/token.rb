# frozen_string_literal: true

require_relative './keys'
require_relative './config'
require_relative './client'
require 'jwt'
require 'securerandom'

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
    key_pair = Keys.load_key KEYS_TARGET_OMEJDN, 'omejdn', create_key: true
    JWT.encode token, key_pair['sk'], 'RS256', { typ: 'at+jwt', kid: key_pair['kid'] }
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
    key_pair = Keys.load_key KEYS_TARGET_OMEJDN, 'omejdn', create_key: true
    JWT.encode token, key_pair['sk'], 'RS256', { typ: 'JWT', kid: key_pair['kid'] }
  end

  # Decodes an access token or id token for inspection
  def self.decode(token, endpoint = nil)
    raise 'No token found' if token.nil? | token.empty?

    args = { algorithm: Config.base_config.dig('access_token', 'algorithm') }
    args.merge!({ aud: "#{Config.base_config['front_url']}#{endpoint}", verify_aud: true }) if endpoint
    JWT.decode(token, Keys.load_key(KEYS_TARGET_OMEJDN, 'omejdn')['sk'].public_key, true, args)[0]
  end
end
