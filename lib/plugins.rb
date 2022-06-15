# frozen_string_literal: true

# Handles calling plugins
class PluginLoader
  class << self; attr_accessor :listeners end
  @configuration = {} # The plugin configuration
  @listeners = {} # A mapping from events to a list of listener functions

  # Load all relevant files
  def self.initialize
    (ENV.fetch('OMEJDN_PLUGINS', nil) || '').split(':').each do |conffile|
      @configuration.merge!(YAML.safe_load(File.read(conffile), fallback: {}, filename: ARGV[1]) || {})
    end

    # Load Custom Plugins
    (@configuration['plugins'] || {}).each do |plugin, _config|
      puts "Loading Plugin: #{plugin}"
      require_relative "./../plugins/#{plugin}/#{plugin}"
    end

    # Register default plugins
    default_plugins = %w[user client config keys] - (@configuration['deactivate_defaults'] || [])
    DefaultClientDB.register if default_plugins.include? 'client'
    DefaultUserDB.register   if default_plugins.include? 'user'
    DefaultConfigDB.register if default_plugins.include? 'config'
    DefaultKeysDB.register   if default_plugins.include? 'keys'
  end

  # Returns any specified configuration options for the plugin
  def self.configuration(plugin)
    @configuration.dig('plugins', plugin) || {}
  end

  # Register a listener
  def self.register(event, listener)
    # p "Plugins: registering #{listener} for event #{event}"
    (@listeners[event] ||= []) << listener
  end

  # Call all listeners and return their values
  def self.fire(event, bind)
    # p "Plugins: Firing event #{event}"
    (@listeners[event] || []).map { |l| l.call(bind) }
  end
end
