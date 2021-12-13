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
  # This function may not assume the existence of any parameter that could be within a request object
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

  # This function ensures a URI is allowed to be used by a client
  def self.verify_redirect_uri(params, client, require_existence)
    unless params[:redirect_uri]
      raise OAuthError, 'invalid_request' if require_existence || [client.redirect_uri].flatten.length != 1

      params[:redirect_uri] = [client.redirect_uri].flatten[0]
    end
    escaped_redir = CGI.unescape(params[:redirect_uri])&.gsub('%20', '+')
    raise OAuthError, 'invalid_request' unless ([client.redirect_uri].flatten + ['localhost']).any? do |uri|
                                                 escaped_redir == uri
                                               end
  end

  def self.retrieve_request_uri(request_uri)
    uri = URI(request_uri)
    Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      res = http.request Net::HTTP::Get.new(uri)
      res.body
    end
  rescue StandardError
    nil
  end

  # Retrieves the request parameters from the URL parameters, for authorization flows
  def self.prepare_params(url_params)
    # We deviate from the OIDC spec in favor of RFC 9101
    # For example, we do not require specifying the scope outside the request parameter,
    # if it is provided within said parameter.
    # On the other hand, we require https!
    jwt, params = nil
    if url_params.key? :request_uri
      raise OAuthError, 'invalid_request' if url_params.key? :request

      if url_params[:request_uri].start_with? 'urn:ietf:params:oauth:request_uri:'
        # Retrieve token from Pushed Authorization Request Cache
        params = PARCache.get[url_params[:request_uri]]
      elsif url_params[:request_uri].start_with? 'https://'
        # Retrieve remote token
        jwt = retrieve_request_uri url_params[:request_uri]
      end
      raise OAuthError, 'invalid_request_uri' unless jwt || params
    elsif url_params.key? :request
      jwt = url_params[:request]
      raise OAuthError, 'invalid_request_object' unless jwt
    end

    if jwt
      client = Client.find_by_id url_params[:client_id]
      raise OAuthError, 'invalid_client' if client.nil?

      params, = Client.decode_jwt jwt, client
      raise OAuthError, 'invalid_client' unless params['client_id'] == url_params[:client_id]
    end

    if params
      url_params.delete(:request_uri)
      url_params.delete(:request)
      url_params.merge! params
    end
    url_params
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

  def self.configuration_metadata(host, path)
    base_config = Config.base_config
    metadata = {}

    # RFC 8414 (also OpenID Connect Core for the most part)
    metadata['issuer'] = base_config.dig('token', 'issuer')
    metadata['authorization_endpoint'] = "#{path}/authorize"
    metadata['token_endpoint'] = "#{path}/token"
    metadata['jwks_uri'] = "#{host}/.well-known/jwks.json"
    # metadata["registration_endpoint"] = "#{host}/FIXME"
    metadata['scopes_supported'] = OAuthHelper.supported_scopes
    metadata['response_types_supported'] = ['code']
    metadata['response_modes_supported'] = ['query'] # FIXME: we only do query atm no fragment
    metadata['grant_types_supported'] = ['authorization_code']
    metadata['token_endpoint_auth_methods_supported'] = %w[none private_key_jwt]
    metadata['token_endpoint_auth_signing_alg_values_supported'] = %w[RS256 RS512 ES256 ES512]
    metadata['service_documentation'] = 'https://github.com/Fraunhofer-AISEC/omejdn-server/wiki'
    # metadata['ui_locales_supported'] =
    # metadata['op_policy_uri'] =
    # metadata['op_tos_uri'] =
    # metadata['revocation_endpoint'] =
    # metadata['revocation_endpoint_auth_methods_supported'] =
    # metadata['revocation_endpoint_auth_signing_alg_values_supported'] =
    # metadata['introspection_endpoint'] =
    # metadata['introspection_endpoint_auth_methods_supported'] =
    # metadata['introspection_endpoint_auth_signing_alg_values_supported'] =
    metadata['code_challenge_methods_supported'] = ['S256']

    # RFC 8628
    # metadata['device_authorization_endpoint'] =

    # RFC 8705
    # metadata['tls_client_certificate_bound_access_tokens'] =
    # metadata['mtls_endpoint_aliases'] =

    # RFC 9101
    metadata['require_signed_request_object'] = true

    # RFC 9126
    metadata['pushed_authorization_request_endpoint'] = "#{path}/par"
    metadata['require_pushed_authorization_requests'] = false

    # RFC-ietf-oauth-jwt-introspection-response-12
    # metadata['introspection_signing_alg_values_supported'] =
    # metadata['introspection_encryption_alg_values_supported'] =
    # metadata['introspection_encryption_enc_values_supported'] =

    # OpenID Connect Discovery 1.0
    metadata['userinfo_endpoint'] = "#{path}/userinfo"
    metadata['acr_values_supported'] = []
    metadata['subject_types_supported'] = 'public'
    metadata['id_token_signing_alg_values_supported'] = base_config.dig('id_token', 'algorithm')
    metadata['id_token_encryption_alg_values_supported'] = ['none']
    metadata['id_token_encryption_enc_values_supported'] = ['none']
    metadata['userinfo_signing_alg_values_supported'] = ['none']
    metadata['userinfo_encryption_alg_values_supported'] = ['none']
    metadata['userinfo_encryption_enc_values_supported'] = ['none']
    metadata['request_object_signing_alg_values_supported'] = %w[RS256 RS512 ES256 ES512]
    metadata['request_object_encryption_alg_values_supported'] = ['none'] # TODO: Implement decryption
    metadata['request_object_encryption_enc_values_supported'] = ['none']
    metadata['display_values_supported'] = ['page'] # TODO: Different UIs
    metadata['claim_types_supported'] = ['normal']
    metadata['claims_supported'] = [] # TODO: What to disclose here?
    # metadata['claims_locales_supported'] =
    metadata['claims_parameter_supported'] = true
    metadata['request_parameter_supported'] = true
    metadata['request_uri_parameter_supported'] = true
    metadata['require_request_uri_registration'] = false

    # Signing as per RFC 8414
    metadata['signed_metadata'] = sign_metadata metadata
    metadata
  end

  def self.sign_metadata(metadata)
    to_sign = metadata.merge
    to_sign['iss'] = to_sign['issuer']
    signing_material = Server.load_skey('token')
    kid = JSON::JWK.new(signing_material['pk'])[:kid]
    JWT.encode to_sign, signing_material['sk'], 'RS256', { kid: kid }
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
