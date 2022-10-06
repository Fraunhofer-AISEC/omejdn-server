# frozen_string_literal: true

require_relative '../../lib/config'
require_relative '../../lib/keys'
require_relative '../../lib/user'
require_relative '../../lib/client'

require 'json'
require 'json-schema'

# Error class for this API
class AdminAPIError < RuntimeError
  attr_reader :type, :code, :desc

  def initialize(type, code = 400, desc = nil)
    super('')
    @type = type
    @code = code
    @desc = desc
  end

  def to_s
    { 'error' => @type, 'error_description' => @desc }.compact.to_json
  end

  UNAUTHORIZED = AdminAPIError.new 'unauthorized', 401
  ACCESS_DENIED = AdminAPIError.new 'access_denied', 403
  MISSING_JSON = AdminAPIError.new 'missing_body'
  MALFORMED_JSON = AdminAPIError.new 'malformed_json'
  INVALID_URL = AdminAPIError.new 'invalid_url_parameters'
  NOT_FOUND = AdminAPIError.new 'does_not_exist', 404
  def self.unacceptable(reason)
    AdminAPIError.new 'unacceptable', 400, reason
  end
end

after '/api/admin/v2/*' do
  headers['Content-Type'] = 'application/json'
end

before '/api/admin/v2/*' do
  return if request.env['REQUEST_METHOD'] == 'OPTIONS'

  begin
    jwt = env.fetch('HTTP_AUTHORIZATION', '')&.slice(7..-1)
    @token = Token.decode jwt, '/api'
    raise 'Client revoked' unless Client.find_by_id @token['client_id']
  rescue StandardError
    raise AdminAPIError::UNAUTHORIZED
  end

  raise AdminAPIError::ACCESS_DENIED unless @token['scope']&.split&.include? 'omejdn:admin'

  begin
    body = request.body.read
    @request_body = JSON.parse body unless body.empty?
  rescue StandardError
    raise AdminAPIError::MALFORMED_JSON
  end

  raise AdminAPIError::MISSING_JSON if !(%w[GET DELETE].include? request.env['REQUEST_METHOD']) && @request_body.nil?
rescue AdminAPIError => e
  halt e.code, e.to_s
end

# ---------- SCHEMAS ----------

def schema_pem(type)
  { 'type' => 'string',
    'pattern' => "^-----BEGIN #{type}-----(\\n|\\r|\\r\\n)" \
                 "([0-9a-zA-Z\+\/=]{64}(\\n|\\r|\\r\\n))*" \
                 "([0-9a-zA-Z\+\/=]{1,63}(\\n|\\r|\\r\\n))?" \
                 "-----END #{type}-----(\\n|\\r|\\r\\n)?$" }
end

def schema_value_or_array(schema)
  { 'oneOf' => [schema, { 'type' => 'array', 'items' => schema }] }
end

SCHEMA_CONFIG = { 'type' => %w[array object] }.freeze
SCHEMA_KEYS = {
  'type' => 'object',
  'properties' => {
    'pk' => (schema_pem 'PUBLIC KEY'),
    'sk' => (schema_pem '(.)* PRIVATE KEY'),
    'certs' => { 'type' => 'array', 'items' => schema_pem('CERTIFICATE') }
  },
  'additionalProperties' => false
}.freeze
SCHEMA_ATTRIBUTES = {
  'type' => 'object',
  'additionalProperties' => {
    'oneOf' => [
      { 'type' => %w[string number array boolean] },
      {
        'type' => 'object',
        'properties' => {
          'value' => {},
          'dynamic' => { 'type' => 'boolean' }
        }
      }
    ]
  }
}.freeze
SCHEMA_USER = {
  'type' => 'object',
  'properties' => {
    'username' => { 'type' => 'string', 'minLength' => 1 },
    'password' => { 'type' => 'string' },
    'attributes' => SCHEMA_ATTRIBUTES,
    'consent' => {
      'type' => 'object',
      'additionalProperties' => {
        'type' => 'array',
        'items' => { 'type' => 'string' }
      }
    },
    'backend' => { 'type' => 'string' },
    'extern' => { 'type' => 'string' }
  },
  'additionalProperties' => false
}.freeze
SCHEMA_UPDATE_USER = {
  'allOf' => [SCHEMA_USER],
  'properties' => { 'extern' => false, 'backend' => false, 'username' => false }
}.freeze
SCHEMA_STRING_OR_STRING_ARRAY = schema_value_or_array({ 'type' => 'string' })
SCHEMA_ENUM_AUTH_METHODS = { 'enum' => %w[none client_secret_basic client_secret_post private_key_jwt] }.freeze
SCHEMA_ENUM_GRANT_TYPES = { 'enum' => %w[authorization_code client_credentials] }.freeze
SCHEMA_URL = { 'type' => 'string', 'pattern' => '^(http|https):\/\/[^ "]+$' }.freeze
SCHEMA_CLIENT = {
  'type' => 'object',
  'properties' => {
    'attributes' => SCHEMA_ATTRIBUTES,
    'backend' => { 'type' => 'string' },
    'client_id' => { 'type' => 'string', 'minLength' => 1 },
    'client_name' => { 'type' => 'string', 'minLength' => 1 },
    'client_uri' => SCHEMA_URL,
    'logo_uri' => SCHEMA_URL,
    'tos_uri' => SCHEMA_URL,
    'policy_uri' => SCHEMA_URL,
    'software_id' => { 'type' => 'string', 'minLength' => 1 },
    'software_version' => { 'type' => 'string', 'minLength' => 1 },
    'contacts' => SCHEMA_STRING_OR_STRING_ARRAY,
    'token_endpoint_auth_method' => SCHEMA_ENUM_AUTH_METHODS,
    'client_secret' => { 'type' => 'string', 'minLength' => 1 },
    'grant_types' => (schema_value_or_array SCHEMA_ENUM_GRANT_TYPES),
    'redirect_uris' => (schema_value_or_array SCHEMA_URL),
    'post_logout_redirect_uris' => (schema_value_or_array SCHEMA_URL),
    'request_uris' => (schema_value_or_array SCHEMA_URL),
    'scope' => SCHEMA_STRING_OR_STRING_ARRAY,
    'resource' => SCHEMA_STRING_OR_STRING_ARRAY
  }
}.freeze
SCHEMA_UPDATE_CLIENT = {
  'allOf' => [SCHEMA_CLIENT],
  'properties' => { 'backend' => false, 'client_id' => false }
}.freeze
SCHEMA_UPDATE_CLIENT_CERTIFICATE = schema_pem 'CERTIFICATE'

# ---------- CONFIGURATION ----------

endpoint '/api/admin/v2/config/:section', ['GET'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (section = params['section']) && section.length.positive?
  raise AdminAPIError::NOT_FOUND   unless (data = Config.read_config(section.to_s))

  halt 200, JSON.generate(data)
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/config/:section', ['PUT'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (section = params['section']) && section.length.positive?

  reason = JSON::Validator.fully_validate(SCHEMA_CONFIG, @request_body)
  raise AdminAPIError.unacceptable(reason) if reason.length.positive?

  existing_section = Config.read_config(section.to_s)
  Config.write_config section.to_s, @request_body
  halt(existing_section ? 204 : 201)
rescue AdminAPIError => e
  halt e.code, e.to_s
end

# ---------- KEY MATERIAL ----------

def pack_keys(k_in)
  {
    'pk' => k_in['pk']&.to_pem,
    'sk' => k_in['sk']&.to_pem,
    'certs' => k_in['certs']&.map { |c| c.to_pem }
  }.compact
end

def unpack_keys(k_in)
  keys = {}
  keys['certs'] = k_in['certs']&.map { |c| OpenSSL::X509::Certificate.new c }
  keys['sk'] = OpenSSL::PKey.read k_in['sk'] if k_in['sk']
  keys['pk'] = OpenSSL::PKey.read k_in['pk'] if k_in['pk']
  # TODO: Consistency checks
  keys['pk'] = keys['sk'].public_key       if keys['pk'].nil? && keys['sk']
  keys['pk'] = keys['certs'][0].public_key if keys['pk'].nil? && keys['certs']&.length&.positive?

  keys.compact
end

endpoint '/api/admin/v2/keys/:target_type', ['GET'], public_endpoint: true do # GET ALL
  raise AdminAPIError::INVALID_URL unless (target_type = params['target_type']) && target_type.length.positive?
  raise AdminAPIError::NOT_FOUND   unless (data = Keys.load_all_keys(target_type))

  halt 200, JSON.generate(data.map { |d| pack_keys(d) })
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/keys/:target_type/:target', ['GET'], public_endpoint: true do # GET
  raise AdminAPIError::INVALID_URL unless (target_type = params['target_type']) && target_type.length.positive?
  raise AdminAPIError::INVALID_URL unless (target = params['target']) && target.length.positive?
  raise AdminAPIError::NOT_FOUND   if     (data = Keys.load_key(target_type, target)).empty?

  halt 200, JSON.generate(pack_keys(data))
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/keys/:target_type/:target', ['PUT'], public_endpoint: true do # SET
  raise AdminAPIError::INVALID_URL unless (target_type = params['target_type']) && target_type.length.positive?
  raise AdminAPIError::INVALID_URL unless (target = params['target']) && target.length.positive?

  reason = JSON::Validator.fully_validate(SCHEMA_KEYS, @request_body)
  raise AdminAPIError.unacceptable(reason) if reason.length.positive?

  existing_keys = Keys.load_key(target_type, target)
  Keys.store_key target_type, target, unpack_keys(@request_body)
  halt(existing_keys.empty? ? 201 : 204)
rescue AdminAPIError => e
  halt e.code, e.to_s
end

# ---------- USERS ----------

def pack_user(user)
  user = user.to_h
  user.delete('password') # Password Hash is useless anyway
  user
end

endpoint '/api/admin/v2/user', ['GET'], public_endpoint: true do
  halt 200, JSON.generate(User.all_users.map { |u| pack_user(u) })
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/user/:username', ['GET'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (username = params['username']) && username.length.positive?
  raise AdminAPIError::NOT_FOUND   unless (data = User.find_by_id(username))

  halt 200, JSON.generate(pack_user(data))
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/user/:username', ['PUT'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (username = params['username']) && username.length.positive?

  reason = JSON::Validator.fully_validate(SCHEMA_UPDATE_USER, @request_body)
  raise AdminAPIError.unacceptable(reason) if reason.length.positive?

  existing_user = User.find_by_id username
  raise AdminAPIError.unacceptable('New user needs a password') if existing_user.nil? && @request_body['password'].nil?

  updated_user = existing_user || User.new
  updated_user.username   ||= username
  updated_user.attributes   = @request_body['attributes'] || updated_user.attributes || {}
  updated_user.consent      = @request_body['consent']    || updated_user.consent    || {}
  updated_user.backend    ||= 'yaml' # TODO
  if existing_user
    updated_user.save
    updated_user.update_password @request_body['password'] if @request_body['password']
    halt 204
  else
    User.add_user updated_user, updated_user.backend
    updated_user.update_password @request_body['password']
    halt 201
  end
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/user/:username', ['DELETE'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (username = params['username']) && username.length.positive?
  raise AdminAPIError::NOT_FOUND   unless User.delete_user(username)

  halt 204
rescue AdminAPIError => e
  halt e.code, e.to_s
end

# ---------- CLIENTS ----------

endpoint '/api/admin/v2/client', ['GET'], public_endpoint: true do
  halt 200, JSON.generate(Client.all_clients.map(&:to_h))
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/client/:client_id', ['GET'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (client_id = params['client_id']) && client_id.length.positive?
  raise AdminAPIError::NOT_FOUND   unless (data = Client.find_by_id(client_id)&.to_h)

  halt 200, JSON.generate(data)
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/client/:client_id', ['PUT'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (client_id = params['client_id']) && client_id.length.positive?

  reason = JSON::Validator.fully_validate(SCHEMA_UPDATE_CLIENT, @request_body)
  raise AdminAPIError.unacceptable(reason) if reason.length.positive?

  existing_client = Client.find_by_id client_id
  updated_client = existing_client || Client.new
  updated_client.attributes = @request_body.delete('attributes') || updated_client.attributes || {}
  updated_client.metadata = @request_body unless @request_body.empty?
  updated_client.metadata['client_id'] = client_id
  updated_client.backend ||= 'yaml' # TODO
  if existing_client
    updated_client.save
    halt 204
  else
    Client.add_client updated_client, updated_client.backend
    halt 201
  end
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/client/:client_id', ['DELETE'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (client_id = params['client_id']) && client_id.length.positive?
  raise AdminAPIError::NOT_FOUND   unless Client.delete_client(client_id)

  halt 204
rescue AdminAPIError => e
  halt e.code, e.to_s
end

# ---------- CLIENT KEYS ----------

endpoint '/api/admin/v2/client/:client_id/certificate', ['GET'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (client_id = params['client_id']) && client_id.length.positive?
  raise AdminAPIError::NOT_FOUND   unless (client = Client.find_by_id(client_id))
  raise AdminAPIError::NOT_FOUND   unless (data = client.certificate)

  halt 200, JSON.generate(data.to_s)
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/client/:client_id/certificate', ['PUT'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (client_id = params['client_id']) && client_id.length.positive?
  raise AdminAPIError::NOT_FOUND   unless (client = Client.find_by_id(client_id))

  reason = JSON::Validator.fully_validate(SCHEMA_UPDATE_CLIENT_CERTIFICATE, @request_body)
  raise AdminAPIError.unacceptable(reason) if reason.length.positive?

  existing_certificate = client.certificate
  client.certificate = OpenSSL::X509::Certificate.new @request_body
  halt(existing_certificate ? 204 : 201)
rescue AdminAPIError => e
  halt e.code, e.to_s
end

endpoint '/api/admin/v2/client/:client_id/certificate', ['DELETE'], public_endpoint: true do
  raise AdminAPIError::INVALID_URL unless (client_id = params['client_id']) && client_id.length.positive?
  raise AdminAPIError::NOT_FOUND   unless (client = Client.find_by_id(client_id))
  raise AdminAPIError::NOT_FOUND   unless client.certificate

  client.certificate = nil
  halt 204
rescue AdminAPIError => e
  halt e.code, e.to_s
end
