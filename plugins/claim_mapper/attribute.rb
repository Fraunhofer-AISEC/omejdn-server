# frozen_string_literal: true

require_relative './_abstract'
require_relative '../../lib/oauth_helper'

# Maps Userinfo Claims to the Access- and ID tokens
# Includes any specifically requested claims as-is
class AttributeClaimMapper < ClaimMapper
  attr_reader :config

  def initialize(config)
    super()
    @config = config || {}
  end

  def map_to_access_token(client, user, scopes, requested_claims, _resources)
    return {} if @config['skip_access_token']

    OAuthHelper.map_claims_to_userinfo (user || client).attributes, requested_claims, client, scopes
  end

  def map_to_id_token(client, user, scopes, requested_claims)
    return {} if @config['skip_id_token']

    OAuthHelper.map_claims_to_userinfo user.attributes, requested_claims, client, scopes
  end
end

# Monkey patch the loader
class PluginLoader
  def self.load_claim_mapper_attribute(config)
    AttributeClaimMapper.new config
  end
end
