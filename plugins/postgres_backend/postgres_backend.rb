# frozen_string_literal: true

require 'pg'

# Load the code for each type of event
require_relative 'storage_config'
require_relative 'storage_keys'
require_relative 'storage_users'
require_relative 'storage_clients'

# The main class for this plugin
class PostgresBackendPlugin
  class << self; attr_accessor :config, :database end
  @config = {} # Database configuration
  @database = nil # Database connection

  # init reads the static configuration
  # and registers the event handlers
  def self.init
    # Default configuration
    @config = {
      # Can contain any postgres connection parameters,
      # see https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-PARAMKEYWORDS
      'connection' => {},
      # Include 'keys', 'config', 'user' and/or 'client' to register the event handlers
      'handlers' => %w[
        keys
        config
        client
        user
      ]
    }.merge(PluginLoader.configuration('postgres_backend') || {})

    # Connect to the db and optionally create the relevant tables.
    # Register any handlers
    db = connect_db
    PostgresClientDB.init db if @config['handlers'].include? 'client'
    PostgresUserDB.init   db if @config['handlers'].include? 'user'
    PostgresConfigDB.init db if @config['handlers'].include? 'config'
    PostgresKeysDB.init   db if @config['handlers'].include? 'keys'
  end

  # A helper to check if a relation exists
  def self.relation_exists(name)
    result = false
    connect_db.exec_params "SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename  = $1", [name] do |res|
      result = res.any?
    end
  end

  # Connects to a database
  def self.connect_db
    PostgresBackendPlugin.database ||= PG.connect @config['connection']
  end
end

# Start initialization upon startup
PostgresBackendPlugin.init
