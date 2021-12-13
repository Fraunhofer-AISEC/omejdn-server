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
  attr_reader :type, :description

  def initialize(type, description = '')
    super('')
    @type = type
    @description = description
  end

  def to_s
    { 'error' => @type, 'error_description' => @description }.to_json
  end
end

# Helper functions for OAuth related tasks
class OAuthHelper
  # Identifies a client from the request parameters and optionally enforces authentication
  def self.identify_client(params, authenticate: true)
    client = nil
    if params[:client_assertion_type] # RFC 7521, Section 4.2
      if params[:client_assertion_type] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client = Client.find_by_jwt params[:client_assertion]
      end
      raise OAuthError.new 'invalid_client', 'Client unknown' if client.nil?

      return client
    end

    raise OAuthError.new 'invalid_client', 'Client unknown' if authenticate

    client = Client.find_by_id params[:client_id]
    raise OAuthError.new 'invalid_client', 'Client unknown' if client.nil?

    client
  end

  # Retrieves the request parameters from the URL parameters, for authorization flows
  def self.prepare_params(url_params)
    # We deviate from the OIDC spec in favor of RFC 9101
    # For example, we do not require specifying the scope outside the request parameter,
    # if it is provided within said parameter.
    # On the other hand, we require https!
    jwt = nil
    params = nil
    if url_params.key? :request_uri
      throw OAuthError.new 'invalid_request' if url_params.key? :request

      if url_params[:request_uri].start_with? 'urn:ietf:params:oauth:request_uri:'
        # Retrieve token from Pushed Authorization Request Cache
        params = PARCache.get[url_params[:request_uri]]
      elsif url_params[:request_uri].start_with? 'https://'
        # Retrieve remote token
        begin
          uri = URI(url_params[:request_uri])
          Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
            res = http.request Net::HTTP::Get.new(uri)
            jwt = res.body
          end
        rescue StandardError
          jwt = nil
        end
      elsif jwt.nil?
        throw OAuthError.new 'invalid_request_uri'
      end
    elsif url_params.key? :request
      jwt = url_params[:request]
      throw OAuthError.new 'invalid_request_object' if jwt.nil?
    end

    return url_params if jwt.nil? && params.nil?

    if jwt
      jwt_untrusted = JWT.decode jwt, nil, false
      throw OAuthError.new 'invalid_client' if jwt_untrusted.dig(0, 'client_id') != url_params[:client_id]

      client = Client.find_by_id url_params[:client_id]
      throw OAuthError.new 'invalid_client' if client.nil?

      aud = Config.base_config['accept_audience']
      params = (JWT.decode jwt, client.certificate&.public_key, true,
                           { nbf_leeway: 30, aud: aud, verify_aud: true, algorithm: jwt_untrusted.dig(1, 'alg') })[0]
    end

    url_params.delete(:request_uri)
    url_params.delete(:request)
    url_params.merge! params
  end

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
    raise OAuthError.new 'invalid_request', "Unsupported verifier method: #{method}" unless method == 'S256'
    raise OAuthError.new 'invalid_request', 'Code verifier missing' if code_verifier.nil?

    digest = Digest::SHA256.new
    digest << code_verifier
    expected_challenge = digest.base64digest.gsub('+', '-').gsub('/', '_').gsub('=', '')
    raise OAuthError.new 'invalid_request', 'Code verifier mismatch' unless expected_challenge == code_challenge
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
