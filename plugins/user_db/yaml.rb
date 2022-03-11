# frozen_string_literal: true

require_relative './_abstract'

# The DB backend for yaml files
class YamlUserDb < UserDb
  attr_reader :config

  def initialize(config)
    super()
    @config = {
      'location' => 'config/users.yml'
    }.merge(config || {})
    Config.write_config(db_file, [].to_yaml) unless File.exist? @config['location']
  end

  def create_user(user)
    users = all_users
    users << user
    write_user_db users
  end

  def delete_user(username)
    user = find_by_id username
    return false unless user

    users = all_users
    users.delete(user)
    write_user_db users
    true
  end

  def update_user(user)
    users = all_users
    idx = users.index user
    return false unless idx

    users[idx] = user
    write_user_db users
    true
  end

  def all_users
    ((YAML.safe_load File.read db_file) || []).map do |user|
      user['backend'] = 'yaml'
      User.from_dict user
    end
  end

  def update_password(user, password)
    user.password = password
    update_user(user)
  end

  def verify_password(user, password)
    user.password == password
  end

  def find_by_id(username)
    ((YAML.safe_load File.read db_file) || []).each do |user|
      next unless user['username'] == username

      user['backend'] = 'yaml'
      return User.from_dict user
    end
    nil
  end

  private

  def db_file
    @config['location']
  end

  def write_user_db(users)
    Config.write_config(db_file, users.map(&:to_dict).map do |u|
                                   u.delete('backend')
                                   u
                                 end.to_yaml)
  end
end

# Monkey patch the loader
class PluginLoader
  def self.load_user_db_yaml(config)
    YamlUserDb.new config
  end
end
