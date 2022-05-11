# frozen_string_literal: true

require_relative 'storage_attributes'

# The PostgreSQL backend for user data. Attributes are saved separately from Metadata
class PostgresUserDB
  TABLE_USERS = 'users'
  def self.get(bind)
    username = bind.local_variable_get :username
    user_hash = {}
    PostgresBackendPlugin.connect_db.exec_params "SELECT * FROM #{TABLE_USERS} WHERE username = $1",
                                                 [username] do |result|
      result.each do |v|
        username, password = v.values_at('username', 'password')
        user_hash['username'] = username
        user_hash['password'] = password
      end
    end
    return nil unless user_hash['username']

    user_hash['attributes'] = PostgresAttributeDB.read_attributes 'user', username
    user_hash['backend']    = 'postgres'
    User.from_h user_hash
  end

  def self.get_all(*)
    users = []
    PostgresBackendPlugin.connect_db.exec_params "SELECT * FROM #{TABLE_USERS}" do |result|
      result.each do |v|
        username, password = v.values_at('username', 'password')
        users << {
          'username' => username,
          'password' => password
        }
      end
    end
    users.each do |c|
      c['attributes'] = PostgresAttributeDB.read_attributes 'user', c['username']
      c['backend']    = 'postgres'
    end
    users.map { |c| User.from_h c }
  end

  def self.create(bind)
    user = bind.local_variable_get :user
    PostgresAttributeDB.write_attributes 'user', user.username, user.attributes
    PostgresBackendPlugin.connect_db.transaction do |t|
      t.exec_params "INSERT INTO #{TABLE_USERS}(username,password) VALUES ($1,$2)",
                    [user.username, user.password]
    end
  end

  def self.update(bind)
    user = bind.local_variable_get :user
    username = user.username
    delete(binding)
    create(binding)
  end

  def self.delete(bind)
    username = bind.local_variable_get :username
    db = PostgresBackendPlugin.connect_db
    db.exec_params "DELETE FROM #{TABLE_USERS} WHERE username = $1", [username]
    PostgresAttributeDB.write_attributes 'user', username, []
  end

  # Forward to key storage
  def self.update_password(bind)
    user = bind.local_variable_get('user')
    password = bind.local_variable_get('password')
    db.exec_params "UPDATE #{TABLE_USERS} SET password = $1 WHERE username = $2",
                   [(User.string_to_pass_hash password), user.username]
  end

  # Forward to key storage
  def self.verify_password(bind)
    user = bind.local_variable_get('user')
    password = bind.local_variable_get('password')
    return unless user.backend == 'postgres'

    user.password == password
  end

  def self.init(db)
    # Create the tables
    unless PostgresBackendPlugin.relation_exists TABLE_USERS
      db.exec_params "CREATE TABLE #{TABLE_USERS} (username TEXT PRIMARY KEY, password TEXT)"
    end
    PostgresAttributeDB.init(db)

    # Register event handlers
    PluginLoader.register 'USER_GET',                            method(:get)
    PluginLoader.register 'USER_GET_ALL',                        method(:get_all)
    PluginLoader.register 'USER_CREATE',                         method(:create)
    PluginLoader.register 'USER_UPDATE',                         method(:update)
    PluginLoader.register 'USER_DELETE',                         method(:delete)
    PluginLoader.register 'USER_AUTHENTICATION_PASSWORD_CHANGE', method(:update_password)
    PluginLoader.register 'USER_AUTHENTICATION_PASSWORD_VERIFY', method(:verify_password)
  end
end
