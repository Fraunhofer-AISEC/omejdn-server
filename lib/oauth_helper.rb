# frozen_string_literal: true

require_relative './config'
require_relative './token_helper'
require 'json'
require 'set'
require 'securerandom'
require 'base64'
require 'digest'

# The OAuth Exception class
class OAuthError < RuntimeError
  attr_reader :reason

  def initialize(reason)
    super
    @reason = reason
  end
end

# Helper functions for OAuth related tasks
class OAuthHelper
  def self.token_response(access_token, scopes, id_token)
    response = {}
    response['access_token'] = access_token
    response['id_token'] = id_token unless id_token.nil?
    response['expires_in'] = Config.base_config.dig('token', 'expiration')
    response['token_type'] = 'bearer'
    response['scope'] = scopes.join ' '
    JSON.generate response
  end

  def self.userinfo(client, user, token)
    req_claims = token.dig('omejdn_reserved', 'userinfo_req_claims')
    userinfo = TokenHelper.map_claims_to_userinfo(user.attributes, req_claims, client, token['scope'].split)
    userinfo['sub'] = user.username
    userinfo
  end

  def self.supported_scopes
    Config.scope_mapping_config.map { |m| m[0] }
  end

  def self.error_response(error, desc = '')
    response = { 'error' => error, 'error_description' => desc }
    JSON.generate response
  end

  def self.new_authz_code
    Base64.urlsafe_encode64(rand(2**512).to_s)
  end

  def self.validate_pkce(code_challenge, code_verifier, method)
    raise unless method == 'S256'

    digest = Digest::SHA256.new
    digest << code_verifier
    expected_challenge = digest.base64digest.gsub('+', '-').gsub('/', '_').gsub('=', '')
    expected_challenge == code_challenge
  end

  def self.generate_jwks
    jwks = JSON::JWK::Set.new
    %w[token id_token].each do |type|
      # Load the signing key
      key_material = [Server.load_skey(type)]
      key_material += Server.load_pkey(type)
      key_material.each do |k|
        # Internally, this creates a KID following RFC 7638 using SHA256
        # Only works with RSA, EC-Keys, and symmetric keys though.
        # Further key types will require upstream changes
        jwk = JSON::JWK.new(k['pk'])
        jwk[:use] = 'sig'
        if k['certs']
          jwk[:x5c] = Server.gen_x5c(k['certs'])
          jwk[:x5t] = Server.gen_x5t(k['certs'])
        end
        jwks << jwk
      end
    end
    jwks.uniq { |k| k['kid'] }
  end

  def self.openid_configuration(host, path)
    base_config = Config.base_config
    metadata = {}
    metadata['issuer'] = base_config.dig('token', 'issuer')
    metadata['authorization_endpoint'] = "#{path}/authorize"
    metadata['token_endpoint'] = "#{path}/token"
    metadata['userinfo_endpoint'] = "#{path}/userinfo"
    metadata['jwks_uri'] = "#{host}/.well-known/jwks.json"
    # metadata["registration_endpoint"] = "#{host}/FIXME"
    metadata['scopes_supported'] = OAuthHelper.supported_scopes
    metadata['response_types_supported'] = ['code']
    metadata['response_modes_supported'] = ['query'] # FIXME: we only do query atm no fragment
    metadata['grant_types_supported'] = ['authorization_code']
    metadata['id_token_signing_alg_values_supported'] = base_config.dig('token', 'algorithm')
    metadata
  end

  def self.adapt_requested_claims(req_claims)
    # https://tools.ietf.org/id/draft-spencer-oauth-claims-00.html#rfc.section.3
    known_sinks = %w[access_token id_token userinfo]
    default_sinks = ['access_token']
    known_sinks.each do |sink|
      req_claims[sink] ||= {}
      req_claims[sink].merge!(req_claims['*'] || {})
    end
    default_sinks.each do |sink|
      req_claims[sink].merge!(req_claims['?'] || {})
    end
    req_claims.delete('*')
    req_claims.delete('?')
    req_claims
  end
end
