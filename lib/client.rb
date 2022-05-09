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

  def certificate
    client = self
    PluginLoader.fire('CLIENT_AUTHENTICATION_CERTIFICATE_GET', binding).compact.first
  end

  def certificate=(new_cert)
    client = self
    PluginLoader.fire('CLIENT_AUTHENTICATION_CERTIFICATE_UPDATE', binding)
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

  def claim?(searchkey, searchvalue = nil)
    attribute = attributes.select { |a| a['key'] == searchkey }.first
    !attribute.nil? && (searchvalue.nil? || attribute['value'] == searchvalue)
  end

  def filter_scopes(scopes)
    (scopes || []) & [*@metadata['scope']]
  end

  def allowed_scoped_attributes(scopes)
    filter_scopes(scopes).map { |s| Config.scope_mapping_config[s] }.compact.flatten.uniq
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
    raise OAuthError, 'invalid_request' unless ([*@metadata['redirect_uris']] + ['localhost']).include? escaped_redir

    uri
  end

  def verify_post_logout_redirect_uri(uri)
    uri ||= [*@metadata['redirect_uris']][0]
    escaped_redir = CGI.unescape(uri)&.gsub('%20', '+')
    return uri if [*@metadata['post_logout_redirect_uris']].include? escaped_redir
  end

  # Decodes a JWT
  def decode_jwt(jwt, verify_aud)
    aud = Config.base_config['accept_audience']
    jwt_dec, = JWT.decode jwt, certificate&.public_key, true,
                          { nbf_leeway: 30, aud: aud, verify_aud: verify_aud, algorithm: %w[RS256 RS512 ES256 ES512] }

    raise 'Not self-issued' if jwt_dec['sub'] && jwt_dec['sub'] != jwt_dec['iss']
    raise 'Wrong Client ID in JWT' if jwt_dec['sub'] && jwt_dec['sub'] != client_id

    jwt_dec
  rescue StandardError => e
    puts "Error decoding JWT #{jwt}: #{e}"
    raise OAuthError.new 'invalid_client', "Error decoding JWT: #{e}"
  end

  # ----- Util -----

  # For convenience, make the client_id a symbol
  def client_id
    @metadata['client_id']
  end

  def client_id=(_new_cid)
    @metadata['client_id'] = newcid
  end

  # client_ids are the primary key for clients
  def ==(other)
    client_id == other.client_id
  end
end

# The default Client DB saves Client Configuration in a dedicated configuration section.
# The exception to this rule are certificates, which are stored in keys/clients/
# in PEM encoded form.
class DefaultClientDB
  def self.get(bind)
    client_id = bind.local_variable_get :client_id
    clients = get_all
    idx = clients.index Client.from_h({ 'client_id' => client_id })
    idx ? clients[idx] : nil
  end

  def self.get_all(*)
    Config.client_config.map { |ccnf| Client.from_h ccnf }
  end

  def self.create(bind)
    new_client = bind.local_variable_get :client
    clients = get_all
    clients << new_client
    Config.client_config = clients.map(&:to_h)
  end

  def self.update(bind)
    client = bind.local_variable_get :client
    clients = get_all
    idx = clients.index client
    clients[idx] = client if idx
    Config.client_config = clients.map(&:to_h)
  end

  def self.delete(bind)
    client_id = bind.local_variable_get :client_id
    clients = get_all
    idx = clients.index Client.from_h({ 'client_id' => client_id })
    clients.delete_at idx if idx
    Config.client_config = clients.map(&:to_h)
  end

  def self.certificate_get(bind)
    client = bind.local_variable_get :client
    key_material = Keys.load_key KEYS_TARGET_CLIENT, client.client_id
    key_material&.dig('certs', 0)
  end

  def self.certificate_update(bind)
    client = bind.local_variable_get :client
    new_cert = bind.local_variable_get :new_cert
    hash = Keys.load_key KEYS_TARGET_CLIENT, client.client_id
    hash['certs'] = new_cert ? [new_cert] : nil
    hash = {} unless hash['sk'] || hash['certs']
    hash['pk'] = (hash['sk'] || hash.dig('certs', 0))&.public_key
    Keys.store_key KEYS_TARGET_CLIENT, client.client_id, hash.compact
  end

  # register functions
  def self.register
    PluginLoader.register 'CLIENT_GET',                               method(:get)
    PluginLoader.register 'CLIENT_GET_ALL',                           method(:get_all)
    PluginLoader.register 'CLIENT_CREATE',                            method(:create)
    PluginLoader.register 'CLIENT_UPDATE',                            method(:update)
    PluginLoader.register 'CLIENT_DELETE',                            method(:delete)
    PluginLoader.register 'CLIENT_AUTHENTICATION_CERTIFICATE_GET',    method(:certificate_get)
    PluginLoader.register 'CLIENT_AUTHENTICATION_CERTIFICATE_UPDATE', method(:certificate_update)
  end
end
