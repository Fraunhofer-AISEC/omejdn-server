# frozen_string_literal: true

require_relative './config'
require 'json'
require 'set'
require 'base64'
require 'digest'

# Represents the error responses to be returned in OAuth Flows
# See https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error
class OAuthError < RuntimeError
  attr_reader :type, :description

  def initialize(type, description = '')
    super('')
    @type = type
    @description = description
  end

  def to_h
    { 'error' => @type, 'error_description' => @description }.compact
  end

  def to_s
    to_h.to_json
  end
end

# Helper functions for OAuth related tasks
class OAuthHelper
  # Identifies a client from the request parameters and enforces authentication
  # This function may not assume the existence of any parameter that could be within a request object
  def self.authenticate_client(params, auth_header)
    # Determine the client, trusting it will use the correct method to tell us
    client_id = params[:client_id]
    if auth_header.start_with? 'Basic'
      client_id, client_secret = Base64.strict_decode64(auth_header.slice(6..-1)).split(':', 2)
    end
    if params[:client_assertion_type] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      client_id = JWT.decode(params[:client_assertion], nil, false).dig(0, 'sub') # Decode without verify
    end
    client = Client.find_by_id client_id
    raise OAuthError.new 'invalid_client', 'Client unknown' if client.nil?

    # Apply the correct authentication method
    # See https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method
    auth_method = client.metadata['token_endpoint_auth_method'] || 'client_secret_basic'
    access = (case auth_method
              when 'client_secret_basic'
                client_secret && client_secret == client.metadata['client_secret']
              when 'client_secret_post'
                params[:client_secret] == client.metadata['client_secret']
              when 'private_key_jwt'
                token = client.decode_jwt params[:client_assertion]
                token && token['sub'] == client.client_id
              when 'none'
                true
              else
                raise OAuthError.new 'invalid_client', 'auth_method not supported'
              end)
    raise OAuthError.new 'invalid_client', 'Client authentication failed' unless access

    client
  end

  # Retrieves the request parameters from the URL parameters, for authorization flows
  def self.prepare_params(params, client)
    # We deviate from the OIDC spec in favor of RFC 9101
    # For example, we do not require specifying the scope outside the request parameter,
    # if it is provided within said parameter.
    # On the other hand, we require https!
    jwt = nil
    if (request_uri = params.delete(:request_uri))
      raise OAuthError.new 'invalid_request', 'request{,_uri}, pick one.' if params.key? :request

      if request_uri.start_with? 'urn:ietf:params:oauth:request_uri:'
        # Retrieve token from Pushed Authorization Request Cache
        params = Cache.par[request_uri]
      elsif client.verify_uri('request_uris', request_uri)
        # Retrieve remote token
        jwt = Net::HTTP.get(URI(request_uri))
      end
      raise OAuthError, 'invalid_request_uri' unless jwt || params
    elsif (request = params.delete(:request))
      jwt = request
      raise OAuthError, 'invalid_request_object' unless jwt
    end

    if jwt
      params = client.decode_jwt jwt
      params&.delete('iss')
      params&.delete('aud')
      params&.transform_keys!(&:to_sym)
    end
    raise OAuthError, 'invalid_client' unless params&.dig(:client_id) == client.client_id

    params
  end

  def self.add_nested_claim(hash, key, value)
    key = key.split('/')
    hash = (hash[key.shift] ||= {}) while key.length > 1
    hash[key.shift] = value
  end

  def self.map_claims_to_userinfo(attrs, claims, scopes)
    new_payload = {}

    # Add attribute if it was requested indirectly through a scope
    scope_mapping = Config.read_config CONFIG_SECTION_SCOPE_MAPPING, {}
    scopes&.map { |s| scope_mapping[s] }&.compact&.flatten&.uniq&.each do |ak|
      next unless (av = attrs[ak])

      av = { 'value' => av } unless av.instance_of?(Hash)
      add_nested_claim new_payload, ak, av if av.key? 'value'
    end

    # Add attribute if it was specifically requested through OIDC claims parameter.
    claims&.each do |ck, cv|
      next unless (av = attrs[ck])

      av = { 'value' => av } unless av.instance_of?(Hash)
      if av['dynamic'] && (req_value = cv['value'] || cv.dig('values', 0))
        add_nested_claim new_payload, ck, req_value
      elsif av.key? 'value'
        add_nested_claim new_payload, ck, av['value']
      end
    end
    new_payload
  end

  def self.validate_pkce(code_challenge, code_verifier, method)
    expected_challenge = generate_pkce(code_verifier, method)
    raise OAuthError.new 'invalid_request', 'Code verifier mismatch' unless expected_challenge == code_challenge
  end

  def self.generate_pkce(code_verifier, method)
    raise OAuthError.new 'invalid_request', "Unsupported verifier method: #{method}" unless method == 'S256'
    raise OAuthError.new 'invalid_request', 'Code verifier missing' if code_verifier.nil?

    digest = Digest::SHA256.new
    digest << code_verifier
    digest.base64digest.gsub('+', '-').gsub('/', '_').gsub('=', '')
  end

  def self.configuration_metadata_oidc_discovery(_base_config, path)
    omejdn_keys = Keys.load_all_keys(KEYS_TARGET_OMEJDN).group_by { |k| k[:use] }
    metadata = {}
    metadata['userinfo_endpoint'] = "#{path}/userinfo"
    metadata['acr_values_supported'] = []
    metadata['subject_types_supported'] = ['public']
    metadata['id_token_signing_alg_values_supported'] = omejdn_keys['sig']&.map { |k| k[:alg] }&.uniq || ['none']
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
    metadata['claims_locales_supported'] = []
    metadata['claims_parameter_supported'] = true
    metadata['request_parameter_supported'] = true
    metadata['request_uri_parameter_supported'] = true
    metadata['require_request_uri_registration'] = true
    metadata
  end

  def self.configuration_metadata_rfc8414(base_config, path)
    metadata = {}
    metadata['issuer'] = base_config['issuer']
    metadata['authorization_endpoint'] = "#{path}/authorize"
    metadata['token_endpoint'] = "#{path}/token"
    metadata['jwks_uri'] = "#{path}/jwks.json"
    # metadata["registration_endpoint"] = "#{host}/FIXME"
    metadata['scopes_supported'] = Config.read_config(CONFIG_SECTION_SCOPE_MAPPING, {}).map { |m| m[0] }
    metadata['scopes_supported'] << 'openid' if Config.base_config['openid']
    metadata['response_types_supported'] = ['code']
    metadata['response_modes_supported'] = %w[query fragment form_post]
    metadata['grant_types_supported'] = %w[authorization_code client_credentials]
    metadata['token_endpoint_auth_methods_supported'] = %w[none client_secret_basic client_secret_post private_key_jwt]
    metadata['token_endpoint_auth_signing_alg_values_supported'] = %w[RS256 RS512 ES256 ES512]
    metadata['service_documentation'] = 'https://github.com/Fraunhofer-AISEC/omejdn-server/wiki'
    metadata['ui_locales_supported'] = []
    # metadata['op_policy_uri'] =
    # metadata['op_tos_uri'] =
    # metadata['revocation_endpoint'] =
    # metadata['revocation_endpoint_auth_methods_supported'] =
    # metadata['revocation_endpoint_auth_signing_alg_values_supported'] =
    # metadata['introspection_endpoint'] =
    # metadata['introspection_endpoint_auth_methods_supported'] =
    # metadata['introspection_endpoint_auth_signing_alg_values_supported'] =
    metadata['code_challenge_methods_supported'] = ['S256']
    metadata
  end

  def self.configuration_metadata
    base_config = Config.base_config
    path = base_config['front_url']
    metadata = {}

    # RFC 8414 (also OpenID Connect Core for the most part)
    metadata.merge!(configuration_metadata_rfc8414(base_config, path))

    # RFC 8628
    # metadata['device_authorization_endpoint'] =

    # RFC 8705
    metadata['tls_client_certificate_bound_access_tokens'] = false
    metadata['mtls_endpoint_aliases'] = {}

    # RFC 9101
    metadata['require_signed_request_object'] = true

    # RFC 9126
    metadata['pushed_authorization_request_endpoint'] = "#{path}/par"
    metadata['require_pushed_authorization_requests'] = false

    # RFC-ietf-oauth-jwt-introspection-response-12
    # metadata['introspection_signing_alg_values_supported'] =
    # metadata['introspection_encryption_alg_values_supported'] =
    # metadata['introspection_encryption_enc_values_supported'] =

    # RFC-ietf-oauth-iss-auth-resp-04
    metadata['authorization_response_iss_parameter_supported'] = true

    # OpenID Connect RP-initiated Logout 1.0 - draft 01
    metadata['end_session_endpoint'] = "#{path}/logout"

    # OpenID Connect Discovery 1.0
    metadata.merge!(configuration_metadata_oidc_discovery(base_config, path))
  end
end
