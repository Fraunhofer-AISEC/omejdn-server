# frozen_string_literal: true

require_rel './_abstract'
require_rel '../../lib/oauth_helper'

# Maps Userinfo Claims to the Access- and ID tokens
# Includes any specifically requested claims as-is
class AttributeClaimMapper < ClaimMapper
  def map_to_access_token(client, user, scopes, requested_claims, _resources)
    OAuthHelper.map_claims_to_userinfo (user || client).attributes, requested_claims, client, scopes
  end

  def map_to_id_token(client, user, scopes, requested_claims)
    OAuthHelper.map_claims_to_userinfo user.attributes, requested_claims, client, scopes
  end
end

# Monkey patch the loader
class PluginLoader
  def self.load_claim_mapper_attribute
    AttributeClaimMapper.new
  end
end
