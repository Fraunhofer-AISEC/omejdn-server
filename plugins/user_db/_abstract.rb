# frozen_string_literal: true

# Abstract UserDb interface
class UserDb
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
