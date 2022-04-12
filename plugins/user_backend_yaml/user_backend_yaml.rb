# frozen_string_literal: true

# The DB backend for yaml files
class YamlUserDb
  attr_reader :config

  def initialize(config)
    @config = {
      'location' => 'config/users.yml'
    }.merge(config || {})
    Config.write_config(db_file, [].to_yaml) unless File.exist? @config['location']

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
    return unless user.backend == 'yaml'

    users = all_users bind
    users << user
    write_user_db users
  end

  def delete_user(bind)
    user = find_by_id bind
    return unless user

    users = all_users bind
    users.delete(user)
    write_user_db users
  end

  def update_user(bind)
    user = bind.local_variable_get('user')
    return unless user.backend == 'yaml'

    users = all_users bind
    idx = users.index user
    return false unless idx

    users[idx] = user
    write_user_db users
    true
  end

  def all_users(_bind)
    ((YAML.safe_load File.read db_file) || []).map do |user|
      user['backend'] = 'yaml'
      User.from_h user
    end
  end

  def update_password(bind)
    user = bind.local_variable_get('user')
    password = bind.local_variable_get('password')
    return unless user.backend == 'yaml'

    user.password = password
    update_user(bind)
  end

  def verify_password(bind)
    user = bind.local_variable_get('user')
    password = bind.local_variable_get('password')
    return unless user.backend == 'yaml'

    user.password == password
  end

  def find_by_id(bind)
    username = bind.local_variable_get 'username'
    ((YAML.safe_load File.read db_file) || []).each do |user|
      next unless user['username'] == username

      user['backend'] = 'yaml'
      return User.from_h user
    end
    nil
  end

  private

  def db_file
    @config['location']
  end

  def write_user_db(users)
    Config.write_config(db_file, users.map(&:to_h).map do |u|
                                   u.delete('backend')
                                   u
                                 end.to_yaml)
  end
end

YamlUserDb.new Config.base_config.dig('plugins', 'user_backend_yaml')
