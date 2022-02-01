# frozen_string_literal: true

require_relative './config'
require 'abstraction'

# Abstract UserDb interface
class UserDb
  abstract

  def create_user(user)
    raise NotImplementedError
  end

  def delete_user(username)
    raise NotImplementedError
  end

  def update_user(user)
    raise NotImplementedError
  end

  def all_users
    raise NotImplementedError
  end

  def find_by_id(user)
    raise NotImplementedError
  end

  def update_password(user, new_password)
    raise NotImplementedError
  end

  def verify_password(user, password)
    raise NotImplementedError
  end
end

# The loader class
class UserDbLoader
  def self.load_db(plugin)
    public_send("load_#{plugin}_db")
  end

  def self.all_dbs
    Config.base_config['user_backend'].map { |plugin| public_send("load_#{plugin}_db") }
  end
end

require 'require_all'
require_rel 'db_plugins'
