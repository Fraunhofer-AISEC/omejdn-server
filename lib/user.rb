# frozen_string_literal: true

require 'bcrypt'
require 'sinatra/activerecord'
require_relative './claim_mapper'
require_relative './user_db'

# Class representing a user from a DB
class User
  include BCrypt

  attr_accessor :username, :password, :attributes, :extern, :backend, :auth_time

  def verify_password(pass)
    UserDbLoader.load_db(backend)&.verify_password(self, pass) || false
  end

  def self.all_users
    UserDbLoader.all_dbs.map(&:all_users).flatten
  end

  def self.find_by_id(username)
    UserDbLoader.all_dbs.each do |db|
      user = db.find_by_id(username)
      return user unless user.nil?
    end
    nil
  end

  def self.from_dict(dict)
    user = User.new
    user.username = dict['username']
    user.attributes = dict['attributes']
    user.extern = dict['extern']
    user.backend = dict['backend']
    user.password = string_to_pass_hash(dict['password']) unless user.extern
    user
  end

  def to_dict
    {
      'username' => username,
      'attributes' => attributes,
      'password' => password&.to_s,
      'extern' => extern,
      'backend' => backend
    }.compact
  end

  def self.delete_user(username)
    !UserDbLoader.all_dbs.index { |db| db.delete_user(username) }.nil?
  end

  def self.add_user(user, user_backend)
    UserDbLoader.load_db(user_backend).create_user(user)
  end

  def save
    UserDbLoader.load_db(backend || Config.base_config['user_backend_default']).update_user(self)
  end

  def update_password(new_password)
    UserDbLoader.load_db(backend).update_password(self, User.string_to_pass_hash(new_password))
  end

  def self.generate_extern_user(provider, json)
    return nil if json[provider['external_userid']].nil?

    username = json[provider['external_userid']]
    user = User.find_by_id(username)
    return user unless user.nil?

    user = User.new
    user.username = username
    user.extern = provider['name'] || false
    user.attributes = []
    user.attributes |= ClaimMapper.map_claims(json, provider) unless provider['claim_mapper'].nil?
    User.add_user(user, Config.base_config['user_backend_default'])
    user
  end

  def claim?(searchkey, searchvalue = nil)
    attribute = attributes.select { |a| a['key'] == searchkey }.first
    if attribute.nil?
      false
    elsif searchvalue.nil?
      true
    else
      attribute['value'] == searchvalue
    end
  end

  # usernames are unique
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
