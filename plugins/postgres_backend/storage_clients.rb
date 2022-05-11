# frozen_string_literal: true

require_relative 'storage_attributes'

# The PostgreSQL backend for client data. Attributes are saved separately from Metadata
class PostgresClientDB
  TABLE_CLIENT_METADATA = 'clients'
  def self.get(bind)
    client_id = bind.local_variable_get :client_id
    client_hash = {}
    PostgresBackendPlugin.connect_db.exec_params "SELECT * FROM #{TABLE_CLIENT_METADATA} WHERE client_id = $1",
                                                 [client_id] do |result|
      result.each do |v|
        key, value = v.values_at('key', 'value')
        client_hash[key] = JSON.parse value
      end
    end
    return nil unless client_hash['client_id']

    client_hash['attributes'] = PostgresAttributeDB.read_attributes 'client', client_id
    client_hash['backend']    = 'postgres'
    Client.from_h client_hash
  end

  def self.get_all(*)
    clients_hash = {}
    PostgresBackendPlugin.connect_db.exec_params "SELECT * FROM #{TABLE_CLIENT_METADATA}" do |result|
      result.each do |v|
        client_id, key, value = v.values_at('client_id', 'key', 'value')
        clients_hash[client_id] ||= {}
        clients_hash[client_id][key] = JSON.parse value
      end
    end
    clients = clients_hash.values
    clients.each do |c|
      c['attributes'] = PostgresAttributeDB.read_attributes 'client', c['client_id']
      c['backend']    = 'postgres'
    end
    clients.map { |c| Client.from_h c }
  end

  def self.create(bind)
    client = bind.local_variable_get :client
    metadata = client.metadata
    PostgresAttributeDB.write_attributes 'client', client.client_id, client.attributes
    PostgresBackendPlugin.connect_db.transaction do |t|
      metadata.each do |key, value|
        t.exec_params "INSERT INTO #{TABLE_CLIENT_METADATA}(client_id,key,value) VALUES ($1,$2,$3)",
                      [client.client_id, key, (JSON.generate value)]
      end
    end
  end

  def self.update(bind)
    client = bind.local_variable_get :client
    client_id = client.client_id
    delete(binding)
    create(binding)
  end

  def self.delete(bind)
    client_id = bind.local_variable_get :client_id
    db = PostgresBackendPlugin.connect_db
    db.exec_params "DELETE FROM #{TABLE_CLIENT_METADATA} WHERE client_id = $1", [client_id]
    PostgresAttributeDB.write_attributes 'client', client_id, []
  end

  # Forward to key storage
  def self.certificate_get(bind)
    DefaultClientDB.certificate_get bind
  end

  # Forward to key storage
  def self.certificate_update(bind)
    DefaultClientDB.certificate_update bind
  end

  def self.init(db)
    # Create the tables
    unless PostgresBackendPlugin.relation_exists TABLE_CLIENT_METADATA
      db.exec_params "CREATE TABLE #{TABLE_CLIENT_METADATA} (client_id TEXT, key TEXT, value TEXT)"
    end
    PostgresAttributeDB.init(db)

    # Register event handlers
    PluginLoader.register 'CLIENT_GET', method(:get)
    PluginLoader.register 'CLIENT_GET_ALL',                           method(:get_all)
    PluginLoader.register 'CLIENT_CREATE',                            method(:create)
    PluginLoader.register 'CLIENT_UPDATE',                            method(:update)
    PluginLoader.register 'CLIENT_DELETE',                            method(:delete)
    PluginLoader.register 'CLIENT_AUTHENTICATION_CERTIFICATE_GET',    method(:certificate_get)
    PluginLoader.register 'CLIENT_AUTHENTICATION_CERTIFICATE_UPDATE', method(:certificate_update)
  end
end
