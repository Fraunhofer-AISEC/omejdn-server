# frozen_string_literal: true

# OAuth client helper class
class Client
  attr_accessor :client_id, :redirect_uri, :name,
                :allowed_scopes, :attributes, :allowed_resources, :request_uri

  def self.find_by_id(client_id)
    load_clients.each do |client|
      return client if client_id == client.client_id
    end
    nil
  end

  def apply_values(ccnf)
    @client_id = ccnf['client_id']
    @redirect_uri = ccnf['redirect_uri']
    @request_uri = ccnf['request_uri']
    @name = ccnf['name']
    @attributes = ccnf['attributes']
    @allowed_scopes = ccnf['allowed_scopes']
    @allowed_resources = ccnf['allowed_resources']
  end

  def self.load_clients
    needs_save = false
    clients = Config.client_config.map do |ccnf|
      client = Client.new
      client.apply_values(ccnf)
      if ccnf['import_certfile']
        begin
          client.certificate = OpenSSL::X509::Certificate.new File.read ccnf['import_certfile']
          needs_save = true
        rescue StandardError => e
          p "Unable to load key ``#{ccnf['import_certfile']}'': #{e}"
        end
      end
      client
    end
    Config.client_config = clients if needs_save
    clients
  end

  def self.from_json(json)
    client = Client.new
    client.apply_values(json)
    client
  end

  # Decodes a JWT and optionally finds the issuing client
  def self.decode_jwt(jwt, client = nil)
    jwt_dec, jwt_hdr = JWT.decode(jwt, nil, false) # Decode without verify

    return nil if jwt['sub'] && jwt_dec['sub'] != jwt_dec['iss']
    return nil unless %w[RS256 RS512 ES256 ES512].include? jwt_hdr['alg']

    client_id = jwt_dec['iss'] || jwt_dec['sub'] || jwt_dec['client_id']
    client ||= find_by_id client_id

    raise 'Client does not exist' if client.nil?

    aud = Config.base_config['accept_audience']
    jwt_dec, = JWT.decode jwt, client.certificate&.public_key, true,
                          { nbf_leeway: 30, aud: aud, verify_aud: true, algorithm: jwt_hdr['alg'] }
    [jwt_dec, client]
  rescue StandardError => e
    puts "Error decoding JWT #{jwt}: #{e}"
    nil
  end

  def to_dict
    result = {
      'client_id' => @client_id,
      'name' => @name,
      'redirect_uri' => @redirect_uri,
      'request_uri' => @request_uri,
      'allowed_scopes' => @allowed_scopes,
      'allowed_resources' => @allowed_resources,
      'attributes' => @attributes
    }
    result.compact!
  end

  def filter_scopes(scopes)
    (scopes || []) & allowed_scopes
  end

  def allowed_scoped_attributes(scopes)
    filter_scopes(scopes).map { |s| Config.scope_mapping_config[s] }.compact.flatten.uniq
  end

  def resources_allowed?(resources)
    @allowed_resources.nil? || (resources - @allowed_resources).empty?
  end

  def request_uri_allowed?(uri)
    [*@request_uri].include? uri
  end

  # This function ensures a URI is allowed to be used by a client
  def verify_redirect_uri(uri, require_existence)
    raise OAuthError, 'invalid_request' if !uri && (require_existence || [*@redirect_uri].length != 1)

    uri ||= [*@redirect_uri][0]
    escaped_redir = CGI.unescape(uri)&.gsub('%20', '+')
    raise OAuthError, 'invalid_request' unless ([*@redirect_uri] + ['localhost']).include? escaped_redir

    uri
  end

  def certificate_file
    "keys/#{Base64.urlsafe_encode64(@client_id)}.cert"
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
end
