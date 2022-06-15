# frozen_string_literal: true

# Plugin to act as an OAuth/OpenID client to federate the login process
# Will only support the authorization code grant type for normal OPs
# Will be extended to support SIOPv2 using the implicit flow

# Goals (Authorization Code):
# + Support most of Omejdn's features
#   + Support Server Metadata
#   + Support Client Authentication methods none, client_secret_basic, client_secret_post, private_key_jwt
#     + private_key_jwt uses our jwks_uri
#   + Support Server Issuer Identification
#   + Always use PKCE if possible
#   + Support Pushed Authorization Requests
# + Optionally use nonce for OpenID requests
# + Cache Server Metadata
# + Configurable Claim Mapping

# Goals (SIOPv2):
# - Support Implicit Flow
# - Support Authorization Code Flow
# - Support Same-Device SIOP
# - Support Cross-Device SIOP
# - Support Dynamic Discovery
# - Support Registration
# - Validate Response correctly

require 'net/http'
require 'rqrcode'
require 'sinatra/streaming'
require_relative './default_attribute_mappers'

# SIOPv2 Static Discovery Metadata
SIOP_V2_STATIC_METADATA = {
  'authorization_endpoint' => 'openid:',
  'issuer' => 'https://self-issued.me/v2',
  'response_types_supported' => ['id_token'],
  'scopes_supported' => ['openid'],
  'subject_types_supported' => ['pairwise'],
  'id_token_signing_alg_values_supported' => ['ES256'],
  'request_object_signing_alg_values_supported' => ['ES256'],
  'subject_syntax_types_supported' => ['urn:ietf:params:oauth:jwk-thumbprint'],
  'id_token_types_supported' => ['subject_signed']
}.freeze

def siop?(provider)
  provider['self-issued'] || false
end

def provider_config
  PluginLoader.configuration('federation')&.dig('providers')
end

def attribute_mapper_config
  PluginLoader.configuration('federation')&.dig('attribute_mappers')
end

def get_login_options(bind)
  login_options = bind.local_variable_get('login_options')
  provider_config.each do |id, options|
    login_options << {
      url: "#{Config.base_config['front_url']}/federation/#{id}",
      desc: (options['description'] || "Login with #{id.capitalize}"),
      logo: options['op_logo_uri']
    }.compact
  end
end
PluginLoader.register 'AUTHORIZATION_LOGIN_STARTED', method(:get_login_options)

# Remembers any sent requests
class FederationCache
  class << self; attr_accessor :cache end
  @cache = {} # indexed by the state parameter
end

# Caches HTTP responses
class UrlCache
  class << self; attr_accessor :cache end
  @cache = {} # contains hashes with expiry and body

  def self.has?(url)
    cached = @cache[url]
    cached = nil if cached && cached[:expiry] < Time.now.to_i
    !cached.nil?
  end

  def self.get(url, force_reload: false)
    return @cache.dig(url, :body) if has?(url) && !force_reload

    # Call the resource
    res = Net::HTTP.get_response(URI(url))
    return nil unless res.is_a?(Net::HTTPSuccess)

    if (cache_control_header = res['Cache-Control'])
      instructions = {}
      cache_control_header.split(',').each do |cc|
        key, value = cc.strip.split('=', 2)
        instructions[key] = value || true
      end

      if (exp = instructions['max-age']&.to_i) # TODO: Respect all other options
        @cache[url] = {
          expiry: Time.now.to_i + exp,
          body: res.body
        }
      end
    end
    res.body
  end
end

def get_metadata(provider)
  return (siop?(provider) ? SIOP_V2_STATIC_METADATA : nil) unless provider['issuer']

  issuer = URI(provider['issuer'])
  metadata_locations = [
    "#{issuer.scheme}://#{issuer.host}:#{issuer.port}/.well-known/oauth-authorization-server#{issuer.path}", # RFC 8414
    "#{issuer.scheme}://#{issuer.host}:#{issuer.port}/.well-known/openid-configuration#{issuer.path}", # RFC 8414 Legacy
    "#{issuer.scheme}://#{issuer.host}:#{issuer.port}#{issuer.path}/.well-known/openid-configuration" # OIDC Discovery
  ]

  if (cached = metadata_locations.filter { |url| UrlCache.has? url }.first)
    metadata = UrlCache.get(cached)
  else
    metadata_locations.each { |url| metadata ||= UrlCache.get url }
  end

  metadata = JSON.parse(metadata)
  metadata['issuer'] == provider['issuer'] ? metadata : nil
end

# A request employing client authentication
def authenticated_post(provider, target, params)
  case provider['token_endpoint_auth_method']
  when 'none'
    params[:client_id] = provider['client_id']
  when 'client_secret_basic'
    http_auth = "Basic #{Base64.strict_encode64("#{provider['client_id']}:#{provider['client_secret']}")}".chomp
  when 'client_secret_post'
    params[:client_id] = provider['client_id']
    params[:client_secret] = provider['client_secret']
  when 'private_key_jwt'
    now = Time.now.to_i
    json = {
      iss: provider['client_id'],
      sub: provider['client_id'],
      aud: provider['issuer'], # Does not support all SIOPs
      exp: now + 60,
      nbf: now,
      iat: now,
      jti: SecureRandom.uuid
    }
    key_pair = Keys.load_key KEYS_TARGET_OMEJDN, 'omejdn'
    params[:client_assertion_type] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    params[:client_assertion] = JWT.encode json, key_pair['sk'], 'RS256', { typ: 'JWT', kid: key_pair['kid'] }
  end

  p params
  post target, params, http_auth
end

def post(target, params, auth_header = nil)
  target = URI(target)
  req = Net::HTTP::Post.new(target)
  req['Authorization'] = auth_header if auth_header
  req.set_form_data params if params
  res = Net::HTTP.start(target.hostname, target.port, use_ssl: target.scheme == 'https') do |http|
    http.request(req)
  end
  res.body
end

before '/federation/:provider_id*' do
  halt 404 unless (@provider = provider_config[params['provider_id']])
  # Try to obtain metadata
  @metadata = @provider['metadata'] || (get_metadata @provider)
  halt 401 unless @metadata
end

def check_prerequisites(mapper, userinfo)
  !((mapper['prerequisites'] || {}).any? do |k, v|
    ([*userinfo[k]] & [*v]).empty?
  end)
end

def generate_extern_user(provider, userinfo)
  base_config = Config.base_config
  username = "#{userinfo['sub']}@#{provider['issuer']}" # Maintain unique usernames
  user = User.find_by_id(username)

  # Add user if they is logging in for the first time
  if user.nil?
    user = User.new
    user.username = username
    user.extern = provider['issuer'] || true
    user.backend = base_config['user_backend_default']
    User.add_user(user, base_config['user_backend_default'])
  end

  # Update local Attributes
  user.attributes = (provider['attribute_mappers'] || []).map do |mapper|
    mapper = attribute_mapper_config&.dig(mapper)
    if check_prerequisites mapper, userinfo
      PluginLoader.fire "PLUGIN_FEDERATION_ATTRIBUTE_MAPPING_#{mapper['type'].upcase}", binding
    end
  end.flatten(2).compact
  user.save

  user
end

def implicit?(provider, metadata)
  siop?(provider) && !metadata['response_types_supported'].include?('code')
end

def jwk_thumbprint(jwk)
  jwk = jwk.clone
  jwk.delete(:kid)
  digest = Digest::SHA256.new
  digest << jwk.sort.to_h.to_json
  digest.base64digest.gsub('+', '-').gsub('/', '_').gsub('=', '')
end

# Redirect the user here to start the flow
endpoint '/federation/:provider_id', ['GET'] do
  code_verifier = SecureRandom.uuid
  oauth_params = {
    response_type: 'code',
    redirect_uri: "#{Config.base_config['front_url']}/federation/#{params['provider_id']}/callback",
    scope: [*@provider['scope']].join(' '),
    nonce: SecureRandom.uuid,
    code_challenge_method: 'S256',
    code_challenge: OAuthHelper.generate_pkce(code_verifier, 'S256'),
    state: SecureRandom.uuid
  }
  if implicit? @provider, @metadata
    # Use Implicit Flow for SIOP if necessary
    oauth_params[:response_type] = 'id_token'
    oauth_params[:response_mode] = 'query'
    oauth_params.delete(:code_challenge_method)
    oauth_params.delete(:code_challenge)
  end

  FederationCache.cache[oauth_params[:state]] = {
    issuer: @provider['issuer'],
    nonce: oauth_params[:nonce],
    code_verifier: code_verifier,
    current_auth: session[:current_auth]
  }

  # Pushed Authorization Requests where possible
  request_params = { client_id: @provider['client_id'] }
  if siop?(@provider) && @provider['client_id'].nil?
    request_params[:client_id] ||= oauth_params[:redirect_uri]
    # Registration
    registration_params = {
      'subject_syntax_types_supported' => ['urn:ietf:params:oauth:jwk-thumbprint'],
      'id_token_signing_alg_values_supported' => %w[RS256 RS512 ES256 ES512]
    }
    if @metadata['registration_endpoint']
      halt 400, 'Dynamic Client Registration is not implemented'
    else
      oauth_params[:registration] = registration_params.to_json
    end
  end

  # TODO: Signing using OIDC Federation?
  if @metadata['pushed_authorization_request_endpoint']
    request_uri = authenticated_post(@provider, @metadata['pushed_authorization_request_endpoint'], oauth_params)
    request_params['request_uri'] = (JSON.parse request_uri)['request_uri']
    halt 400, "PAR failed: #{request_uri}" unless request_params['request_uri']
  else
    request_params.merge! oauth_params
  end

  # Start Authorization Flow
  request_url = "#{@metadata['authorization_endpoint']}?#{URI.encode_www_form request_params}"
  if siop?(@provider)
    request_params[:response_mode] = 'post'
    cross_device_request_url = "#{@metadata['authorization_endpoint']}?#{URI.encode_www_form request_params}"
    siop_haml = File.read 'plugins/federation/federation_siop.haml'
    halt 200, (haml siop_haml, locals: {
      state: oauth_params[:state],
      provider_id: params['provider_id'],
      href: request_url,
      cross_device_href: cross_device_request_url,
      qr: RQRCode::QRCode.new(cross_device_request_url).as_svg(module_size: 4)
    })
  else
    redirect to(request_url)
  end
end

# This endpoint is for notifying the open browser window
# when login is done on another device (see SIOP Cross-Device Callback below)
get '/federation/:provider_id/stream', provides: 'text/event-stream' do
  halt 400, 'Cache' unless params['state'] && (cached = FederationCache.cache[params['state']])
  stream :keep_open do |out|
    cached[:callback_stream] = out
    out.callback { cached.delete(:callback_stream) }
  end
end

# SIOP Cross-Device Callback
# We just signal to the open browser window to complete the callback
# at the normal callback endpoint below
endpoint '/federation/:provider_id/callback', ['POST'] do
  halt 400, 'Cache' unless params['state'] && (cached = FederationCache.cache[params['state']])
  halt 400, 'Stream not available' unless (out = cached[:callback_stream])
  params.delete('provider_id')
  out << "data: #{URI.encode_www_form params}\n\n"
  out.flush
end

# Callback endpoint
endpoint '/federation/:provider_id/callback', ['GET'] do
  halt 400, 'Cache' unless params['state'] && (cached = FederationCache.cache.delete(params['state']))

  # Authorization Server Issuer Identification (RFC 9207)
  halt 400, 'ISS' if @metadata['authorization_response_iss_parameter_supported'] && params['iss'] != cached[:issuer]

  # Restore cached auth context handler
  session[:current_auth] = cached[:current_auth]

  # Error handling
  if params['error']
    halt 400,
         "Error: The Federation partner responded with #{params['error']}: #{params['error_description']}"
  end

  # Get id_token and userinfo
  if implicit? @provider, @metadata
    halt 400, 'No ID Token' unless (id_token = params['id_token'])
    userinfo, = JWT.decode id_token, nil, false
  else
    # Get Access Token
    token_params = {
      grant_type: 'authorization_code',
      code: params['code'],
      redirect_uri: "#{Config.base_config['front_url']}/federation/#{params['provider_id']}/callback",
      code_verifier: cached[:code_verifier]
    }
    token_response = (JSON.parse authenticated_post(@provider, @metadata['token_endpoint'], token_params))
    halt 400, 'No access Token' unless (access_token = token_response['access_token'])
    halt 400, 'No ID Token' unless (id_token = token_response['id_token'])

    # Get Userinfo
    userinfo = post(@metadata['userinfo_endpoint'], nil, "Bearer #{access_token}")
    userinfo = JSON.parse(userinfo)
  end

  # Verify ID Token
  if siop? @provider
    # Since we know already that we are looking for a SIOP id_token, we deviate slightly from the draft
    # and throw errors whenever something goes bad.
    # Verify signature
    id_token, = JWT.decode id_token, nil, true, { algorithms: %w[RS256 RS512 ES256 ES512] } do |_header, body|
      # We only support JWK-Thumbprints atm.
      JWT::JWK.import(body['sub_jwk']).keypair.public_key
    end
    # Verify self-signedness
    halt 400, 'wrong sub' if id_token['sub'] != jwk_thumbprint(id_token['sub_jwk'])
    halt 400, 'not self-issued' if id_token['iss'] != id_token['sub']
    client_id = "#{Config.base_config['front_url']}/federation/#{params['provider_id']}/callback"
    halt 400, 'wrong audience' if id_token['aud'] != client_id
  else
    jwks = ->(o) { JSON.parse(UrlCache.get(@metadata['jwks_uri'], force_reload: o[:invalidate])) }
    id_token, = JWT.decode id_token, nil, true, { algorithms: %w[RS256 RS512 ES256 ES512], jwks: jwks }
  end

  halt 400, 'wrong nonce' if id_token['nonce'] != cached[:nonce]

  user = generate_extern_user(@provider, userinfo)
  user.auth_time = id_token['auth_time'] || Time.now.to_i
  login_finished user, false, remember_me: true
end
