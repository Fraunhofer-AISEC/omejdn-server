# frozen_string_literal: true

# OAuth client helper class
class Client
  attr_accessor :client_id, :redirect_uri, :name,
                :allowed_scopes, :attributes, :allowed_resources

  def self.find_by_id(client_id)
    load_clients.each do |client|
      return client if client_id == client.client_id
    end
    nil
  end

  def apply_values(ccnf)
    @client_id = ccnf['client_id']
    @redirect_uri = ccnf['redirect_uri']
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

  def self.extract_jwt_cid(jwt)
    begin
      jwt_dec, jwt_hdr = JWT.decode(jwt, nil, false) # Decode without verify
      return nil unless jwt_dec['sub'] == jwt_dec['iss']
      return nil unless %w[RS256 RS512 ES256 ES512].include? jwt_hdr['alg']
    rescue StandardError => e
      puts "Error decoding JWT #{jwt}: #{e}"
      return nil
    end
    [jwt_hdr['alg'], jwt_dec['sub']]
  end

  def self.find_by_jwt(jwt)
    clients = load_clients
    puts "looking for client of #{jwt}" if Config.base_config['app_env'] != 'production'
    jwt_alg, jwt_cid = extract_jwt_cid jwt
    return nil if jwt_cid.nil?

    clients.each do |client|
      next unless client.client_id == jwt_cid

      puts "Client #{jwt_cid} found"
      # Try verify
      aud = Config.base_config['accept_audience']
      JWT.decode jwt, client.certificate&.public_key, true,
                 { nbf_leeway: 30, aud: aud, verify_aud: true, algorithm: jwt_alg }
      return client
    rescue StandardError => e
      puts "Tried #{client.name}: #{e}" if Config.base_config['app_env'] != 'production'
      return nil
    end
    puts "ERROR: Client #{jwt_cid} does not exist"
    nil
  end

  def to_dict
    result = {
      'client_id' => @client_id,
      'name' => @name,
      'redirect_uri' => @redirect_uri,
      'allowed_scopes' => @allowed_scopes,
      'attributes' => @attributes
    }
    result['allowed_resources'] = @allowed_resources unless @allowed_resources.nil?
    result
  end

  def filter_scopes(scopes)
    (scopes || []).select { |s| allowed_scopes.include? s }
  end

  def allowed_scoped_attributes(scopes)
    filter_scopes(scopes).map { |s| Config.scope_mapping_config[s] }.compact.flatten.uniq
  end

  def resources_allowed?(resources)
    return true if @allowed_resources.nil?

    resources.reject { |r| @allowed_resources.include? r }.empty?
  end

  def certificate_file
    "keys/#{Base64.urlsafe_encode64(@client_id)}.cert"
  end

  def certificate
    begin
      filename = certificate_file
      return nil unless File.exist? filename # no cert registered

      cert = OpenSSL::X509::Certificate.new File.read filename
      now = Time.now
      return cert unless cert.not_after < now || cert.not_before > now
    rescue StandardError => e
      p "Unable to load key ``#{filename}'': #{e}"
    end
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
