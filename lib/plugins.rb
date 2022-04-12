# frozen_string_literal: true

# Handles calling plugins
class PluginLoader
  class << self; attr_accessor :listeners end
  @listeners = {} # A mapping from events to a list of listener functions

  # Load all relevant files
  def self.initialize
    (Config.base_config['plugins'] || {}).each do |plugin, _config|
      puts "Loading Plugin: #{plugin}"
      require_relative "./../plugins/#{plugin}/#{plugin}"
    end
  end

  # Register a listener
  def self.register(event, listener)
    # p "Plugins: registering #{listener} for event #{event}"
    (@listeners[event] ||= []) << listener
  end

  # Call all listeners and return their values
  def self.fire(event, bind)
    p "Plugins: Firing event #{event}"
    (@listeners[event] || []).map { |l| l.call(bind) }
  end
end
