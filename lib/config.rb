# frozen_string_literal: true

require 'yaml'
CONFIG_SECTION_OMEJDN            = 'omejdn'
CONFIG_SECTION_CLIENTS           = 'clients'
CONFIG_SECTION_USERS             = 'users'
CONFIG_SECTION_OAUTH_PROVIDERS   = 'oauth_providers'
CONFIG_SECTION_SCOPE_DESCRIPTION = 'scope_description'
CONFIG_SECTION_SCOPE_MAPPING     = 'scope_mapping'
CONFIG_SECTION_WEBFINGER         = 'webfinger'
DEFAULT_SCOPE_MAPPING = {
  # Omejdn API scopes
  'omejdn:read' => ['omejdn'],
  'omejdn:write' => ['omejdn'],
  'omejdn:admin' => ['omejdn'],
  # OpenID scopes
  'profile' => %w[name family_name given_name middle_name nickname preferred_username profile picture
                  website gender birthdate zoneinfo locale updated_at],
  'email' => %w[email email_verified],
  'address' => %w[formatted street_address locality region postal_code country],
  'phone' => %w[phone_number phone_number_verified]
}.freeze
DEFAULT_SCOPE_DESCRIPTION = {
  'omejdn:read' => 'Read access to the Omejdn server API',
  'omejdn:write' => 'Write access to the Omejdn server API',
  'omejdn:admin' => 'Access to the Omejdn server admin API',
  'profile' => 'Standard profile claims (e.g.: Name, picture, website, gender, birthdate, location)',
  'email' => 'Email-Address',
  'address' => 'Address',
  'phone' => 'Phone-number'
}.freeze

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

  def self.scope_description_config=(config)
    write_config(CONFIG_SECTION_SCOPE_DESCRIPTION, config)
  end

  def self.scope_mapping_config
    read_config CONFIG_SECTION_SCOPE_MAPPING, {}
  end

  def self.scope_mapping_config=(config)
    write_config(CONFIG_SECTION_SCOPE_MAPPING, config)
  end

  def self.webfinger_config
    read_config CONFIG_SECTION_WEBFINGER, {}
  end

  def self.webfinger_config=(config)
    write_config(CONFIG_SECTION_WEBFINGER, config)
  end

  # Fill missing values in the configuration
  # This will create a configuration if necessary
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

    # Scope Mapping
    scope_mapping = scope_mapping_config
    scope_mapping = DEFAULT_SCOPE_MAPPING if scope_mapping.empty?
    Config.scope_mapping_config = scope_mapping

    # Scope Description
    scope_description = scope_description_config
    scope_description = DEFAULT_SCOPE_DESCRIPTION if scope_description.empty?
    Config.scope_description_config = scope_description

    # Webfinger (Fallback is default)
    webfinger = webfinger_config
    Config.webfinger_config = webfinger

    # Save base configuration and return it
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
    return fallback unless File.exist? "#{CONFIG_DIR}/#{section}.yml"

    (YAML.safe_load (File.read "#{CONFIG_DIR}/#{section}.yml"), fallback: fallback,
                                                                filename: "#{CONFIG_DIR}/#{section}.yml") || fallback
  end

  # register functions
  def self.register
    PluginLoader.register 'CONFIGURATION_STORE', method(:write_config)
    PluginLoader.register 'CONFIGURATION_LOAD',  method(:read_config)
  end
end
