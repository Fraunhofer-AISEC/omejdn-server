# frozen_string_literal: true

require 'bcrypt'
require_relative './plugins'

# Class representing a user from a DB
class User
  attr_accessor :username, :password, :attributes, :extern, :backend, :auth_time, :consent

  # ----- Implemented by plugins -----

  def self.find_by_id(username)
    PluginLoader.fire('USER_GET', binding).flatten.compact.first
  end

  def self.all_users
    PluginLoader.fire('USER_GET_ALL', binding).flatten
  end

  def self.add_user(user, user_backend)
    PluginLoader.fire('USER_CREATE', binding)
  end

  def self.delete_user(username)
    PluginLoader.fire('USER_DELETE', binding)
  end

  def save
    user = self
    PluginLoader.fire('USER_UPDATE', binding)
  end

  def verify_password(password)
    user = self
    PluginLoader.fire('USER_AUTHENTICATION_PASSWORD_VERIFY', binding).compact.first || false
  end

  def update_password(password)
    user = self
    PluginLoader.fire('USER_AUTHENTICATION_PASSWORD_CHANGE', binding)
  end

  # ----- Conversion to/from hash for import/export -----

  def self.from_h(dict)
    user = User.new
    user.username = dict['username']
    user.attributes = dict['attributes']
    user.extern = dict['extern']
    user.backend = dict['backend']
    user.consent = dict['consent']
    user.password = string_to_pass_hash(dict['password']) unless user.extern
    user
  end

  def to_h
    {
      'username' => username,
      'attributes' => attributes,
      'password' => password&.to_s,
      'extern' => extern,
      'backend' => backend,
      'consent' => consent
    }.compact
  end

  # ----- Whether the user has such an attribute -----

  def claim?(searchkey, searchvalue = nil)
    attribute = attributes.select { |a| a['key'] == searchkey }.first
    !attribute.nil? && (searchvalue.nil? || attribute['value'] == searchvalue)
  end

  # ----- Util -----

  # usernames are the primary key for users
  def ==(other)
    username == other.username
  end

  def self.string_to_pass_hash(str)
    if BCrypt::Password.valid_hash? str
      BCrypt::Password.new str
    else
      BCrypt::Password.create str
    end
  end
end

# The default User DB saves User Configuration in a dedicated configuration section
class DefaultUserDB
  def self.create_user(bind)
    user = bind.local_variable_get('user')
    return unless user.backend == 'yaml'

    users = get_all bind
    users << user
    Config.user_config = users.map(&:to_h)
  end

  def self.delete_user(bind)
    user = get bind
    return unless user

    users = get_all bind
    users.delete(user)
    Config.user_config = users.map(&:to_h)
  end

  def self.update_user(bind)
    user = bind.local_variable_get('user')
    return unless user.backend == 'yaml'

    users = get_all bind
    idx = users.index user
    return false unless idx

    users[idx] = user
    Config.user_config = users.map(&:to_h)
    true
  end

  def self.get_all(_bind)
    Config.user_config.map do |user|
      user['backend'] = 'yaml'
      User.from_h user
    end
  end

  def self.update_password(bind)
    user = bind.local_variable_get('user')
    password = bind.local_variable_get('password')
    return unless user.backend == 'yaml'

    user.password = User.string_to_pass_hash password
    update_user(bind)
  end

  def self.verify_password(bind)
    user = bind.local_variable_get('user')
    password = bind.local_variable_get('password')
    return unless user.backend == 'yaml'

    user.password == password
  end

  def self.get(bind)
    username = bind.local_variable_get 'username'
    Config.user_config.each do |user|
      next unless user['username'] == username

      user['backend'] = 'yaml'
      return User.from_h user
    end
    nil
  end

  # register functions
  def self.register
    PluginLoader.register 'USER_GET',                            method(:get)
    PluginLoader.register 'USER_GET_ALL',                        method(:get_all)
    PluginLoader.register 'USER_CREATE',                         method(:create_user)
    PluginLoader.register 'USER_UPDATE',                         method(:update_user)
    PluginLoader.register 'USER_DELETE',                         method(:delete_user)
    PluginLoader.register 'USER_AUTHENTICATION_PASSWORD_CHANGE', method(:update_password)
    PluginLoader.register 'USER_AUTHENTICATION_PASSWORD_VERIFY', method(:verify_password)
  end
end
