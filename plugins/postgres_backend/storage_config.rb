# frozen_string_literal: true

# The PostgreSQL backend for configuration data uses two schemas.
# Arrays are saved as single JSON-encoded values, while
# Hashes are saved as key-value pairs
class PostgresConfigDB
  TABLE_CONFIG_PREFIX = 'configuration_'

  # To write a config section, we overwrite everything
  def self.write_config(bind)
    section = bind.local_variable_get :section
    data    = bind.local_variable_get :data
    table_name = TABLE_CONFIG_PREFIX + section # FIXME: Possible SQL Injection
    PostgresBackendPlugin.connect_db.transaction do |t|
      case data.class.name
      when 'Array'
        t.exec_params "CREATE TABLE #{table_name}(item TEXT)" unless PostgresBackendPlugin.relation_exists table_name
        t.exec_params "DELETE FROM #{table_name}"
        data.each do |item|
          t.exec_params "INSERT INTO #{table_name}(item) VALUES ($1)", [JSON.generate(item)]
        end
      when 'Hash'
        unless PostgresBackendPlugin.relation_exists table_name
          t.exec_params "CREATE TABLE #{table_name}(key TEXT PRIMARY KEY, value TEXT)"
        end
        t.exec_params "DELETE FROM #{table_name}"
        data.each do |key, value|
          t.exec_params "INSERT INTO #{table_name}(key,value) VALUES ($1,$2)", [key.to_s, JSON.generate(value)]
        end
      end
    end
  end

  # To read a config section, we use the fallback to determine the type
  def self.read_config(bind)
    section  = bind.local_variable_get :section
    fallback = bind.local_variable_get :fallback
    table_name = TABLE_CONFIG_PREFIX + section
    retval = nil
    PostgresBackendPlugin.connect_db.exec_params "SELECT * FROM #{table_name}" do |result|
      case fallback.class.name
      when 'Array'
        retval = []
        result.each { |v| retval << (JSON.parse v.values_at('item')) }
      when 'Hash'
        retval = {}
        result.each do |v|
          key, value = v.values_at('key', 'value')
          retval[key] = JSON.parse value
        end
      else
        retval = fallback # Unknown type
      end
    end
    retval
  rescue StandardError => e
    p e unless e.is_a? PG::UndefinedTable # Config section not yet written to, ignore...
    fallback
  end

  def self.init(_db)
    # Register event handlers
    PluginLoader.register 'CONFIGURATION_STORE', method(:write_config)
    PluginLoader.register 'CONFIGURATION_LOAD',  method(:read_config)
  end
end
