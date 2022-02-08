# frozen_string_literal: true

require 'require_all'

# Extend this by an appropriate function to load a Plugin
class PluginLoader
  # Load all relevant files
  def self.initialize
    (Config.base_config['plugins'] || {}).each do |type, plugins|
      plugins.each do |name, _plugin_config|
        puts "Loading Plugin (#{type}): #{name}"
        require_rel "../plugins/#{type}/#{name}"
      end
    end
  end

  # Load one particular Plugin
  # Should return the corresponding interface for that type
  def self.load_plugin(type, name)
    public_send("load_#{type}_#{name}", Config.base_config.dig('plugins', type, name))
  end

  # Load all plugins of a type
  def self.load_plugins(type)
    (Config.base_config.dig('plugins', type) || []).map do |name, plugin_config|
      public_send("load_#{type}_#{name}", plugin_config)
    end
  end
end
