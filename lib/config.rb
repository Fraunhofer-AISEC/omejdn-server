# frozen_string_literal: true

require 'yaml'
CONFIG_SECTION_OMEJDN            = 'omejdn'
CONFIG_SECTION_CLIENTS           = 'clients'
CONFIG_SECTION_USERS             = 'users'
CONFIG_SECTION_OAUTH_PROVIDERS   = 'oauth_providers'
CONFIG_SECTION_SCOPE_DESCRIPTION = 'scope_description'
CONFIG_SECTION_SCOPE_MAPPING     = 'scope_mapping'
CONFIG_SECTION_WEBFINGER         = 'webfinger'

# Configuration helpers functions
class Config
  def self.write_config(section, data)
    PluginLoader.fire('CONFIGURATION_STORE', binding)
  end

  def self.read_config(section, fallback)
    PluginLoader.fire('CONFIGURATION_LOAD', binding).first
  end

  def self.client_config
    read_config CONFIG_SECTION_CLIENTS, []
  end

  def self.client_config=(config)
    write_config(CONFIG_SECTION_CLIENTS, config)
  end

  def self.user_config
    read_config CONFIG_SECTION_USERS, []
  end

  def self.user_config=(config)
    write_config(CONFIG_SECTION_USERS, config)
  end

  def self.base_config
    read_config CONFIG_SECTION_OMEJDN, {}
  end

  def self.base_config=(config)
    write_config CONFIG_SECTION_OMEJDN, config
  end

  def self.oauth_provider_config
    read_config CONFIG_SECTION_OAUTH_PROVIDERS, []
  end

  def self.oauth_provider_config=(providers)
    write_config(CONFIG_SECTION_OAUTH_PROVIDERS, providers)
  end

  def self.scope_description_config
    read_config CONFIG_SECTION_SCOPE_DESCRIPTION, {}
  end

  def self.scope_mapping_config
    read_config CONFIG_SECTION_SCOPE_MAPPING, {}
  end

  def self.webfinger_config
    read_config CONFIG_SECTION_WEBFINGER, {}
  end

  def self.webfinger_config=(config)
    write_config(CONFIG_SECTION_WEBFINGER, config)
  end

  # Fill missing values in the main configuration
  # This will create a configuration file if necessary
  def self.setup
    # Load existing configuration
    config = base_config

    # Fill in default values
    apply_env(config, 'issuer',           'http://localhost:4567')
    apply_env(config, 'front_url',        config['issuer'])
    apply_env(config, 'bind_to',          '0.0.0.0:4567')
    apply_env(config, 'environment',      'development')
    apply_env(config, 'openid',           false)
    apply_env(config, 'default_audience', [])
    apply_env(config, 'accept_audience',  [config['issuer'], "#{config['front_url']}/token"])
    %w[access_token id_token].each do |token|
      apply_env(config, "#{token}.expiration", 3600)
      apply_env(config, "#{token}.algorithm",  'RS256')
    end

    # Save configuration file
    Config.base_config = config
  end

  def self.apply_env(config, conf_key, fallback)
    conf_parts = conf_key.split('.')
    env_value = ENV.fetch("OMEJDN_#{conf_parts.join('__').upcase}", nil)
    conf_key = conf_parts.pop
    conf_parts.each do |part|
      config[part] ||= {}
      config = config[part]
    end
    env_value = env_value.to_i if begin
      Integer(env_value)
    rescue StandardError
      false
    end
    env_value = false if env_value == 'false'
    env_value = true if env_value == 'true'
    config[conf_key] = env_value || config[conf_key] || fallback
  end

  # Initialize admin user if given in ENV
  def self.create_admin
    return unless ENV['OMEJDN_ADMIN']

    admin_name, admin_pw = ENV['OMEJDN_ADMIN'].split(':')
    admin = User.find_by_id(admin_name)
    unless admin
      admin = User.from_h({
                            'username' => admin_name,
                            'attributes' => [{ 'key' => 'omejdn', 'value' => 'admin' }]
                          })
      User.add_user(admin, Config.base_config['user_backend_default'])
    end
    admin.update_password(admin_pw)
  end
end

# DefaultConfigDB saves Configuration Data as YAML files on disk
class DefaultConfigDB
  CONFIG_DIR = 'config'

  def self.write_config(bind)
    section = bind.local_variable_get :section
    data    = bind.local_variable_get :data
    file = File.new "#{CONFIG_DIR}/#{section}.yml", File::CREAT | File::TRUNC | File::RDWR
    file.write data.to_yaml
    file.close
  end

  def self.read_config(bind)
    section  = bind.local_variable_get :section
    fallback = bind.local_variable_get :fallback
    (YAML.safe_load (File.read "#{CONFIG_DIR}/#{section}.yml"), fallback: fallback,
                                                                filename: "#{CONFIG_DIR}/#{section}.yml") || fallback
  end

  # register functions
  def self.register
    PluginLoader.register 'CONFIGURATION_STORE', method(:write_config)
    PluginLoader.register 'CONFIGURATION_LOAD',  method(:read_config)
  end
end
