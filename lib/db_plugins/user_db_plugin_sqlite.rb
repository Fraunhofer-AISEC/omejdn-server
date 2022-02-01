# frozen_string_literal: true

require 'sqlite3'

# The SQlite DB plugin for users
class SqliteUserDb < UserDb
  def create_user(user)
    db = connect_db
    db.execute 'CREATE TABLE IF NOT EXISTS password(username TEXT PRIMARY KEY, password TEXT)'
    db.execute 'CREATE TABLE IF NOT EXISTS attributes(username TEXT, key TEXT, value TEXT, PRIMARY KEY (username, key))'
    db.execute 'INSERT INTO password(username, password) VALUES(?, ?)', user.username, user.password
    user.attributes.each do |attribute|
      db.execute 'INSERT INTO attributes (username, key, value) VALUES (?, ?, ?)', user.username, attribute['key'],
                 attribute['value']
    end
    db.close
  end

  def delete_user(username)
    db = connect_db
    return false unless user_in_db(username, db)

    db.execute 'DELETE FROM password   WHERE username=?', username
    db.execute 'DELETE FROM attributes WHERE username=?', username
    true
  end

  def update_user(user)
    db = connect_db
    return false unless user_in_db(user.username, db)

    db.execute 'DELETE FROM attributes WHERE username=?', user.username
    user.attributes.each do |attribute|
      db.execute 'INSERT OR REPLACE INTO attributes (username, key, value) VALUES (?, ?, ?)', user.username,
                 attribute['key'], attribute['value']
    end
    db.close
    true
  end

  def verify_password(user, password)
    user.password == password
  end

  def all_users
    db = connect_db
    users = db.execute 'SELECT * FROM password'
    users.each do |user|
      user['backend'] = 'sqlite'
      user['attributes'] =
        db.execute 'SELECT key, value FROM attributes WHERE attributes.username = ?', user['username']
    end
    db.close
    users.map { |user| User.from_dict user }
  end

  def update_password(user, password)
    db = connect_db
    return false unless user_in_db(user.username, db)

    db.execute 'UPDATE password SET password=? WHERE username=?', password, user.username
  end

  def find_by_id(username)
    db = connect_db
    user = db.execute 'SELECT * FROM password WHERE username=?', username
    return nil if user.empty?

    user = user[0]
    user['attributes'] = db.execute 'SELECT key, value FROM attributes WHERE attributes.username = ?', username
    user['backend'] = 'sqlite'
    User.from_dict user
  end

  def connect_db
    db = SQLite3::Database.open Config.user_backend_config.dig('sqlite', 'location')
    db.results_as_hash = true
    db
  end

  def user_in_db(_username, db)
    (db.execute 'SELECT EXISTS(SELECT 1 FROM password WHERE username=?)', user.username).dig(0, 0) == 1
  end
end

# Monkey patch the loader
class UserDbLoader
  def self.load_sqlite_db
    SqliteUserDb.new
  end
end
