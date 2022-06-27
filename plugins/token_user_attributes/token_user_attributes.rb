# frozen_string_literal: true

require_relative '../../lib/oauth_helper'

# Maps Userinfo Claims to the Access- and ID tokens
# Includes any specifically requested claims as-is
class TokenUserAttributesPlugin
  attr_reader :config

  def initialize(config)
    @config = config || {}
    PluginLoader.register 'TOKEN_CREATED_ACCESS_TOKEN', method(:map_to_access_token)
    PluginLoader.register 'TOKEN_CREATED_ID_TOKEN',     method(:map_to_id_token)
  end

  def map_to_access_token(bind)
    map_to_token bind, 'access_token' unless @config['skip_access_token']
  end

  def map_to_id_token(bind)
    map_to_token bind, 'id_token' unless @config['skip_id_token']
  end

  def map_to_token(bind, sink)
    token  = bind.local_variable_get 'token'
    client = bind.local_variable_get 'client'
    user   = bind.local_variable_get 'user'
    scopes = bind.local_variable_get 'scopes'
    claims = bind.local_variable_get 'claims'
    token.merge!(OAuthHelper.map_claims_to_userinfo((user || client).attributes, claims[sink], client, scopes))
  end
end

TokenUserAttributesPlugin.new PluginLoader.configuration('token_user_attributes')
