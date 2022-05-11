# frozen_string_literal: true

# The PostgreSQL backend for keys stores values indexed by target_type, target and type
# The cryptographic items themselves are stored as PEM
class PostgresKeysDB
  TABLE_KEYS = 'keys'
  CERTIFICATE_CHAIN_SEPARATOR = '_'

  def self.store_key(bind)
    target_type  = bind.local_variable_get :target_type
    target       = bind.local_variable_get :target
    key_material = bind.local_variable_get :key_material

    PostgresBackendPlugin.connect_db.transaction do |t|
      t.exec_params "DELETE FROM #{TABLE_KEYS} WHERE target_type = $1 AND target = $2", [target_type, target]
      if key_material['sk']
        t.exec_params "INSERT INTO #{TABLE_KEYS}(target_type,target,type,value) VALUES ($1,$2,$3,$4)",
                      [target_type, target, 'sk', key_material['sk'].to_pem]
      end
      if key_material['certs']
        t.exec_params "INSERT INTO #{TABLE_KEYS}(target_type,target,type,value) VALUES ($1,$2,$3,$4)",
                      [target_type, target, 'certs',
                       key_material['certs'].map(&:to_pem).join(CERTIFICATE_CHAIN_SEPARATOR)]
      end
    end
  end

  def self.load_key(bind)
    target_type = bind.local_variable_get :target_type
    target      = bind.local_variable_get :target
    db = PostgresBackendPlugin.connect_db
    retval = {}
    db.exec_params "SELECT * FROM #{TABLE_KEYS} WHERE target_type = $1 AND target = $2",
                   [target_type, target] do |result|
      result.each do |v|
        key, value = v.values_at('type', 'value')
        case key
        when 'sk'
          retval[key] = OpenSSL::PKey::RSA.new value
        when 'certs'
          retval[key] = value.split(CERTIFICATE_CHAIN_SEPARATOR).map do |c|
            OpenSSL::X509::Certificate.new c
          end
        end
      end
    end
    retval['pk'] = retval.dig('certs', 0)&.public_key || retval['sk']&.public_key
    retval
  end

  def self.load_all_keys(bind)
    target_type = bind.local_variable_get :target_type
    db = PostgresBackendPlugin.connect_db
    retval = {}
    db.exec_params "SELECT * FROM #{TABLE_KEYS} WHERE target_type = $1", [target_type] do |result|
      result.each do |v|
        target, key, value = v.values_at('target', 'type', 'value')
        retval[target] ||= {}
        case key
        when 'sk'
          retval[target][key] = OpenSSL::PKey::RSA.new value
        when 'certs'
          retval[target][key] = value.split(CERTIFICATE_CHAIN_SEPARATOR).map do |c|
            OpenSSL::X509::Certificate.new c
          end
        end
      end
    end
    retval = retval.values
    retval.each { |k| k['pk'] = k.dig('certs', 0)&.public_key || k['sk']&.public_key }
    retval
  end

  def self.init(db)
    # Create the table
    unless PostgresBackendPlugin.relation_exists TABLE_KEYS
      db.exec_params "CREATE TABLE #{TABLE_KEYS} (target_type TEXT, target TEXT, type TEXT, value TEXT)"
    end

    # register handlers
    PluginLoader.register 'KEYS_STORE',          method(:store_key)
    PluginLoader.register 'KEYS_LOAD',           method(:load_key)
    PluginLoader.register 'KEYS_LOAD_ALL',       method(:load_all_keys)
  end
end
