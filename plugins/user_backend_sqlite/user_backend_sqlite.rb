# frozen_string_literal: true

require 'sqlite3'

# The SQlite DB plugin for users
class SqliteUserDb
  attr_reader :config

  def initialize(config)
    @config = {
      'location' => 'config/users.db'
    }.merge(config || {})
    unless File.exist? @config['location']
      db = connect_db
      db.execute 'CREATE TABLE password(username TEXT PRIMARY KEY, password TEXT)'
      db.execute 'CREATE TABLE attributes(username TEXT, key TEXT, value TEXT, PRIMARY KEY (username, key))'
      db.close
    end

    PluginLoader.register 'USER_GET',                            method(:find_by_id)
    PluginLoader.register 'USER_GET_ALL',                        method(:all_users)
    PluginLoader.register 'USER_CREATE',                         method(:create_user)
    PluginLoader.register 'USER_UPDATE',                         method(:update_user)
    PluginLoader.register 'USER_DELETE',                         method(:delete_user)
    PluginLoader.register 'USER_AUTHENTICATION_PASSWORD_CHANGE', method(:update_password)
    PluginLoader.register 'USER_AUTHENTICATION_PASSWORD_VERIFY', method(:verify_password)
  end

  def create_user(bind)
    user = bind.local_variable_get('user')
    return unless user.backend == 'sqlite'

    db = connect_db
    db.execute 'INSERT INTO password(username, password) VALUES(?, ?)', user.username, user.password
    user.attributes.each do |attribute|
      db.execute 'INSERT INTO attributes (username, key, value) VALUES (?, ?, ?)', user.username, attribute['key'],
                 attribute['value']
    end
    db.close
  end

  def delete_user(bind)
    username = bind.local_variable_get('username')
    db = connect_db
    return unless user_in_db(username, db)

    db.execute 'DELETE FROM password   WHERE username=?', username
    db.execute 'DELETE FROM attributes WHERE username=?', username
  end

  def update_user(bind)
    user = bind.local_variable_get('user')
    return unless user.backend == 'sqlite'

    db = connect_db
    return unless user_in_db(user.username, db)

    db.execute 'DELETE FROM attributes WHERE username=?', user.username
    user.attributes.each do |attribute|
      db.execute 'INSERT OR REPLACE INTO attributes (username, key, value) VALUES (?, ?, ?)', user.username,
                 attribute['key'], attribute['value']
    end
    db.close
    true
  end

  def verify_password(bind)
    user = bind.local_variable_get('user')
    password = bind.local_variable_get('password')
    return unless user.backend == 'sqlite'

    user.password == password
  end

  def all_users(_bind)
    db = connect_db
    users = db.execute 'SELECT * FROM password'
    users.each do |user|
      user['backend'] = 'sqlite'
      user['attributes'] =
        db.execute 'SELECT key, value FROM attributes WHERE attributes.username = ?', user['username']
    end
    db.close
    users.map { |user| User.from_h user }
  end

  def update_password(bind)
    user = bind.local_variable_get('user')
    password = bind.local_variable_get('password')
    return unless user.backend == 'sqlite'

    db = connect_db
    return false unless user_in_db(user.username, db)

    db.execute 'UPDATE password SET password=? WHERE username=?', password, user.username
  end

  def find_by_id(bind)
    username = bind.local_variable_get 'username'
    db = connect_db
    user = db.execute 'SELECT * FROM password WHERE username=?', username
    return nil if user.empty?

    user = user[0]
    user['attributes'] = db.execute 'SELECT key, value FROM attributes WHERE attributes.username = ?', username
    user['backend'] = 'sqlite'
    User.from_h user
  end

  def connect_db
    db = SQLite3::Database.open @config['location']
    db.results_as_hash = true
    db
  end

  def user_in_db(_username, db)
    (db.execute 'SELECT EXISTS(SELECT 1 FROM password WHERE username=?)', user.username).dig(0, 0) == 1
  end
end

SqliteUserDb.new Config.base_config.dig('plugins', 'user_backend_sqlite')
