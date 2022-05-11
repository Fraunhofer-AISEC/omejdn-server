# frozen_string_literal: true

# User Attributes for users and clients
class PostgresAttributeDB
  TABLE_ATTRIBUTES = 'attributes'
  def self.write_attributes(type, identifier, attributes)
    PostgresBackendPlugin.connect_db.transaction do |t|
      t.exec_params "DELETE FROM #{TABLE_ATTRIBUTES} WHERE type = $1 AND identifier = $2", [type, identifier]
      attributes.each do |a|
        t.exec_params "INSERT INTO #{TABLE_ATTRIBUTES}(type,identifier,key,value) VALUES ($1,$2,$3,$4)",
                      [type, identifier, a['key'], (JSON.generate a['value'])]
      end
    end
  end

  def self.read_attributes(type, identifier)
    db = PostgresBackendPlugin.connect_db
    db.exec_params "SELECT * FROM #{TABLE_ATTRIBUTES} WHERE type = $1 AND identifier = $2",
                   [type, identifier] do |result|
      retval = []
      result.each do |v|
        key, value = v.values_at('key', 'value')
        retval << { 'key' => key, 'value' => (JSON.parse value) }
      end
      return retval
    end
    []
  end

  def self.init(db)
    # Create table
    return if PostgresBackendPlugin.relation_exists TABLE_ATTRIBUTES

    db.exec_params "CREATE TABLE #{TABLE_ATTRIBUTES} (type TEXT, identifier TEXT, key TEXT, value TEXT)"
  end
end
