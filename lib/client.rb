# frozen_string_literal: true

# OAuth Client
class Client
  attr_accessor :client_id, :metadata, :attributes

  def self.find_by_id(client_id)
    load_clients.each do |client|
      return client if client_id == client.client_id
    end
    nil
  end

  def apply_values(ccnf)
    @client_id = ccnf.delete('client_id')
    @attributes = ccnf.delete('attributes') || []
    @metadata = ccnf
  end

  def self.load_clients
    needs_save = false
    clients = Config.client_config.map do |ccnf|
      import = ccnf.delete('import_certfile')
      client = Client.new
      client.apply_values(ccnf)
      if import
        begin
          client.certificate = OpenSSL::X509::Certificate.new File.read import
          needs_save = true
        rescue StandardError => e
          p "Unable to load key ``#{import}'': #{e}"
        end
      end
      client
    end
    Config.client_config = clients if needs_save
    clients
  end

  def self.from_dict(json)
    client = Client.new
    client.apply_values(json)
    client
  end

  # Decodes a JWT
  def decode_jwt(jwt, verify_aud)
    _, jwt_hdr = JWT.decode(jwt, nil, false) # Decode without verify
    aud = Config.base_config['accept_audience']
    jwt_dec, = JWT.decode jwt, certificate&.public_key, true,
                          { nbf_leeway: 30, aud: aud, verify_aud: verify_aud, algorithm: jwt_hdr['alg'] }

    raise 'Not self-issued' if jwt_dec['sub'] && jwt_dec['sub'] != jwt_dec['iss']
    raise 'Wrong Client ID in JWT' if jwt_dec['sub'] && jwt_dec['sub'] != @client_id

    jwt_dec
  rescue StandardError => e
    puts "Error decoding JWT #{jwt}: #{e}"
    raise OAuthError.new 'invalid_client', "Error decoding JWT: #{e}"
  end

  def to_dict
    result = { 'client_id' => @client_id }.merge(@metadata)
    result['attributes'] = @attributes
    result.compact
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

  def claim?(searchkey, searchvalue = nil)
    attribute = attributes.select { |a| a['key'] == searchkey }.first
    !attribute.nil? && (searchvalue.nil? || attribute['value'] == searchvalue)
  end

  def certificate_file
    "keys/clients/#{Base64.urlsafe_encode64(@client_id)}.cert"
  end

  def certificate
    cert = OpenSSL::X509::Certificate.new File.read certificate_file
    raise 'Certificate expired' if cert.not_after < Time.now
    raise 'Certificate not yet valid' if cert.not_before > Time.now

    cert
  rescue StandardError => e
    p "Unable to load key ``#{certificate_file}'': #{e}"
    nil
  end

  def certificate=(new_cert)
    # delete the certificate if set to nil
    filename = certificate_file
    if new_cert.nil?
      File.delete filename if File.exist? filename
      return
    end
    File.write(filename, new_cert)
  end

  def ==(other)
    client_id == other.client_id
  end
end
