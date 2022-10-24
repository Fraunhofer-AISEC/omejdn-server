# frozen_string_literal: true

require_relative './plugins'

# Class representing an OAuth Client
class Client
  attr_accessor :metadata, :attributes, :backend

  # ----- Implemented by plugins -----

  def self.find_by_id(client_id)
    PluginLoader.fire('CLIENT_GET', binding).flatten.compact.first
  end

  def self.all_clients
    PluginLoader.fire('CLIENT_GET_ALL', binding).flatten
  end

  def self.add_client(client, client_backend)
    PluginLoader.fire('CLIENT_CREATE', binding)
  end

  def self.delete_client(client_id)
    PluginLoader.fire('CLIENT_DELETE', binding)
  end

  def save
    client = self
    PluginLoader.fire('CLIENT_UPDATE', binding)
  end

  # ----- Conversion to/from hash for import/export -----

  def self.from_h(dict)
    client = Client.new
    client.attributes = dict.delete('attributes') || []
    client.metadata = dict
    client
  end

  def to_h
    {
      'attributes' => @attributes
    }.merge(@metadata).compact
  end

  def filter_scopes(scopes)
    (scopes || []) & [*@metadata['scope']]
  end

  def grant_type_allowed?(grant_type)
    [*(@metadata['grant_types'] || ['authorization_code'])].include? grant_type
  end

  def resources_allowed?(resources)
    @metadata['resource'].nil? || (resources - [*@metadata['resource']]).empty?
  end

  def request_uri_allowed?(uri)
    [*@metadata['request_uris']].include? uri
  end

  # This function ensures a URI is allowed to be used by a client
  def verify_redirect_uri(uri, require_existence)
    raise OAuthError, 'invalid_request' if !uri && (require_existence || [*@metadata['redirect_uris']].length != 1)

    uri ||= [*@metadata['redirect_uris']][0]
    escaped_redir = CGI.unescape(uri)&.gsub('%20', '+')
    raise OAuthError, 'invalid_request' unless [*@metadata['redirect_uris']].include? escaped_redir

    uri
  end

  def verify_uri(type, uri)
    uri && [*@metadata[type]].include?(CGI.unescape(uri)&.gsub('%20', '+'))
  end

  # Decodes a JWT
  def decode_jwt(jwt)
    jwks = lambda do |_options|
      if @metadata['jwks']
        @metadata['jwks']
      elsif @metadata['jwks_uri']
        # TODO: Caching and cache invalidation
        JSON.parse(Net::HTTP.get(URI(@metadata[:jwks_uri])))
      else
        JWT::JWK::Set.new
      end
    end
    decode_options = {
      nbf_leeway: 30,
      aud: Config.base_config['accept_audience'],
      verify_aud: true,
      iss: client_id,
      verify_iss: true,
      algorithm: %w[RS256 RS512 ES256 ES512]
    }
    # JWT cannot currently handle missing KIDs
    payload, = JWT.decode jwt, nil, true, decode_options do |header, _body|
      keys = JWT::JWK::Set.new(jwks.call({}))
      kid = header['kid'] || header[:kid]
      keys.filter! { |k| k[:kid] == kid } if kid
      keys.first&.keypair # FIXME: public_key is kinda broken for EC
    end
    payload
  rescue StandardError => e
    p e
    nil
  end

  # ----- Util -----

  # For convenience, make the client_id a symbol
  def client_id
    @metadata['client_id']
  end

  def client_id=(new_cid)
    @metadata['client_id'] = new_cid
  end

  # client_ids are the primary key for clients
  def ==(other)
    client_id == other.client_id
  end
end

# The default Client DB saves Client Configuration in a dedicated configuration section.
# The exception to this rule is JWKS, which is stored in Key Targets
class DefaultClientDB
  CONFIG_SECTION_CLIENTS = 'clients'
  KEYS_TARGET_CLIENTS = 'clients'

  def self.get(bind)
    client_id = bind.local_variable_get :client_id
    client = get_all(nil, keys: false).find { |c| c.client_id == client_id }
    return unless client

    client.metadata['jwks'] = Keys.load_keys(KEYS_TARGET_CLIENTS, client.client_id).export
    client
  end

  def self.get_all(_bind = nil, keys: true)
    clients = Config.read_config(CONFIG_SECTION_CLIENTS, []).map { |ccnf| Client.from_h ccnf }
    clients.each { |c| c.metadata['jwks'] = Keys.load_keys(KEYS_TARGET_CLIENTS, c.client_id).export } if keys
    clients
  end

  def self.create(bind)
    client = bind.local_variable_get :client
    clients = get_all nil, keys: false
    clients << client
    Keys.store_keys KEYS_TARGET_CLIENTS, client.client_id, JWT::JWK::Set.new(client.metadata.delete('jwks') || {})
    Config.write_config(CONFIG_SECTION_CLIENTS, clients.map(&:to_h))
  end

  def self.update(bind)
    client = bind.local_variable_get :client
    clients = get_all nil, keys: false
    idx = clients.index client
    clients[idx] = client if idx
    Keys.store_keys KEYS_TARGET_CLIENTS, client.client_id, JWT::JWK::Set.new(client.metadata.delete('jwks') || {})
    Config.write_config(CONFIG_SECTION_CLIENTS, clients.map(&:to_h))
  end

  def self.delete(bind)
    client_id = bind.local_variable_get :client_id
    clients = get_all nil, keys: false
    clients.delete Client.from_h({ 'client_id' => client_id })
    Keys.store_keys KEYS_TARGET_CLIENTS, client_id, JWT::JWK::Set.new
    Config.write_config(CONFIG_SECTION_CLIENTS, clients.map(&:to_h))
  end

  # register functions
  def self.register
    PluginLoader.register 'CLIENT_GET',                               method(:get)
    PluginLoader.register 'CLIENT_GET_ALL',                           method(:get_all)
    PluginLoader.register 'CLIENT_CREATE',                            method(:create)
    PluginLoader.register 'CLIENT_UPDATE',                            method(:update)
    PluginLoader.register 'CLIENT_DELETE',                            method(:delete)
  end
end
