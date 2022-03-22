# frozen_string_literal: true

# Abstract ClaimMapper interface
class ClaimMapper
  # Used to map additional claims into the access token
  def map_to_access_token(_client, _user, _scopes, _requested_claims, _resources)
    {}
  end

  # Used to map additional claims into the id token
  def map_to_id_token(_client, _user, _scopes, _requested_claims)
    {}
  end

  # Used to generate external users
  def map_from_provider(claims, provider)
    raise NotImplementedError
  end
end
