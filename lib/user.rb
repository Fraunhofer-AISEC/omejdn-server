# frozen_string_literal: true

require 'bcrypt'
require_relative './plugins'

# Class representing a user from a DB
class User
  attr_accessor :username, :password, :attributes, :extern, :backend, :auth_time

  def verify_password(password)
    user = self
    PluginLoader.fire('USER_AUTHENTICATION_PASSWORD_VERIFY', binding).compact.first || false
  end

  def update_password(password)
    user = self
    PluginLoader.fire('USER_AUTHENTICATION_PASSWORD_CHANGE', binding)
  end

  def save
    user = self
    PluginLoader.fire('USER_UPDATE', binding)
  end

  def claim?(searchkey, searchvalue = nil)
    attribute = attributes.select { |a| a['key'] == searchkey }.first
    !attribute.nil? && (searchvalue.nil? || attribute['value'] == searchvalue)
  end

  # usernames are unique
  def ==(other)
    username == other.username
  end

  def self.all_users
    PluginLoader.fire('USER_GET_ALL', binding).flatten
  end

  def self.find_by_id(username)
    PluginLoader.fire('USER_GET', binding).flatten.compact.first
  end

  def self.from_h(dict)
    user = User.new
    user.username = dict['username']
    user.attributes = dict['attributes']
    user.extern = dict['extern']
    user.backend = dict['backend']
    user.password = string_to_pass_hash(dict['password']) unless user.extern
    user
  end

  def to_h
    {
      'username' => username,
      'attributes' => attributes,
      'password' => password&.to_s,
      'extern' => extern,
      'backend' => backend
    }.compact
  end

  def self.delete_user(username)
    PluginLoader.fire('USER_DELETE', binding)
  end

  def self.add_user(user, user_backend)
    PluginLoader.fire('USER_CREATE', binding)
  end

  def self.string_to_pass_hash(str)
    if BCrypt::Password.valid_hash? str
      BCrypt::Password.new str
    else
      BCrypt::Password.create str
    end
  end
end
