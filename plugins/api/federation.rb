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
# - Configurable Claim Mapping

require 'net/http'

provider_config = {
  'omejdn' => {
    'issuer' => 'http://localhost:4568', # REQUIRED
    'grant_type' => 'authorization_code', # Defaults to 'authorization_code'. Can be 'implicit' for SIOPv2
    #    'metadata' => { # For those Servers that neither implemented RFC 8414 nor OIDC Discovery correctly
    #      'token_endpoint' => 'https://oauth2.googleapis.com/token',
    #      'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/v2/auth',
    #      'userinfo_endpoint' => 'https://openidconnect.googleapis.com/v1/userinfo',
    #      'jwks_uri' => 'https://www.googleapis.com/oauth2/v3/certs'
    #    },
    'client_id' => 'myAwesomeClientId', # REQUIRED
    'token_endpoint_auth_method' => 'private_key_jwt', # Defaults to 'client_secret_basic'
    'client_secret' => 'mySuperSecretSecret', # CONDITIONAL if auth method requires it
    'scope' => %w[openid profile] # REQUIRED
  }
}

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

  def self.get(url)
    return @cache.dig(url, :body) if has? url

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
  return nil unless provider['issuer']

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
    http_auth = "Basic #{Base64.encode64("#{provider['client_id']}:#{provider['client_secret']}")}".chomp
  when 'client_secret_post'
    params[:client_id] = provider['client_id']
    params[:client_secret] = provider['client_secret']
  when 'private_key_jwt'
    now = Time.now.to_i
    json = {
      iss: provider['client_id'],
      sub: provider['client_id'],
      aud: provider['issuer'],
      exp: now + 60,
      nbf: now,
      iat: now,
      jti: SecureRandom.uuid
    }
    key_pair = Keys.load_skey
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

def generate_extern_user(provider, userinfo)
  username = "#{userinfo['sub']}@#{provider['issuer']}" # Maintain unique usernames
  user = User.find_by_id(username)

  # Add user if they is logging in for the first time
  if user.nil?
    user = User.new
    user.username = username
    user.extern = provider['issuer'] || false
    User.add_user(user, Config.base_config['user_backend_default'])
  end

  # Update local Attributes
  user.attributes = [*provider['claim_mapper']].map do |mapper|
    PluginLoader.load_plugin('claim_mapper', mapper).map_from_provider(userinfo, provider)
  end.flatten(1)
  user.save

  user
end

# Redirect the user here to start the flow
endpoint '/federation/:provider_id', ['GET'] do
  code_verifier = SecureRandom.uuid
  oauth_params = {
    response_type: 'code',
    response_mode: 'query',
    redirect_uri: "#{Config.base_config['front_url']}/federation/#{params['provider_id']}/callback",
    scope: [*@provider['scope']].join(' '),
    nonce: SecureRandom.uuid,
    code_challenge_method: 'S256',
    code_challenge: OAuthHelper.generate_pkce(code_verifier, 'S256'),
    state: SecureRandom.uuid
  }

  FederationCache.cache[oauth_params[:state]] = {
    issuer: @provider['issuer'],
    nonce: oauth_params[:nonce],
    code_verifier: code_verifier,
    current_auth: session[:current_auth]
  }

  # Pushed Authorization Requests where possible
  request_params = { client_id: @provider['client_id'] }
  if @metadata['pushed_authorization_request_endpoint']
    request_uri = authenticated_post(@provider, @metadata['pushed_authorization_request_endpoint'], oauth_params)
    request_params['request_uri'] = (JSON.parse request_uri)['request_uri']
    halt 400, "PAR failed: #{request_uri}" unless request_params['request_uri']
  else
    request_params.merge! oauth_params
  end

  redirect to("#{@metadata['authorization_endpoint']}?#{URI.encode_www_form request_params}")
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

  # Get Access Token
  token_params = {
    grant_type: 'authorization_code',
    code: params['code'],
    redirect_uri: "#{Config.base_config['front_url']}/federation/#{params['provider_id']}/callback",
    code_verifier: cached[:code_verifier]
  }
  token_response = (JSON.parse authenticated_post(@provider, @metadata['token_endpoint'], token_params))

  # Verify OpenID nonce
  halt 400 unless token_response['nonce'] == cached['nonce']

  halt 400 unless (access_token = token_response['access_token'])
  _id_token = token_response['id_token'] # TODO: Evaluate authentication, verify signature

  userinfo_response = post(@metadata['userinfo_endpoint'], nil, "Bearer #{access_token}")
  user = generate_extern_user(@provider, JSON.parse(userinfo_response))

  user.auth_time = Time.now.to_i # TODO: Should be the time from the ID Token
  session[:user] = SecureRandom.uuid
  Cache.user_session[session[:user]] = user
  auth = Cache.authorization[session[:current_auth]]
  update_auth_scope auth, user, (Client.find_by_id auth[:client_id])
  next_task AuthorizationTask::LOGIN
end
