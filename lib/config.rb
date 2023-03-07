# frozen_string_literal: true

require 'yaml'
CONFIG_SECTION_OMEJDN            = 'omejdn'
CONFIG_SECTION_SCOPE_DESCRIPTION = 'scope_description'
CONFIG_SECTION_SCOPE_MAPPING     = 'scope_mapping'
CONFIG_SECTION_WEBFINGER         = 'webfinger'
DEFAULT_SCOPE_MAPPING = {
  # OpenID scopes
  'profile' => %w[name family_name given_name middle_name nickname preferred_username profile picture
                  website gender birthdate zoneinfo locale updated_at],
  'email' => %w[email email_verified],
  'address' => %w[address/formatted address/street_address address/locality address/region address/postal_code
                  address/country],
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

  def self.read_config(section, fallback = nil)
    PluginLoader.fire('CONFIGURATION_LOAD', binding).first || fallback
  end

  def self.base_config
    read_config CONFIG_SECTION_OMEJDN, {}
  end

  def self.base_config=(config)
    write_config CONFIG_SECTION_OMEJDN, config
  end

  # Fill missing values in the configuration
  # This will create a configuration if necessary
  def self.setup
    # Load existing configuration
    config = base_config

    # Base/Main Configuration
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
    scope_mapping = read_config(CONFIG_SECTION_SCOPE_MAPPING) || DEFAULT_SCOPE_MAPPING
    write_config(CONFIG_SECTION_SCOPE_MAPPING, scope_mapping)

    # Scope Description
    scope_description = read_config(CONFIG_SECTION_SCOPE_DESCRIPTION) || DEFAULT_SCOPE_DESCRIPTION
    write_config(CONFIG_SECTION_SCOPE_DESCRIPTION, scope_description)

    # Webfinger
    webfinger = read_config(CONFIG_SECTION_WEBFINGER) || {}
    write_config(CONFIG_SECTION_WEBFINGER, webfinger)

    # Save base configuration and return it
    Config.base_config = config
  end

  def self.apply_env(config, key, fallback)
    key = key.split('.')
    env_value = ENV.fetch("OMEJDN_#{key.join('__').upcase}", nil)
    config = (config[key.shift] ||= {}) while key.length > 1
    conf_key = key.shift
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
      admin = User.from_h({ 'username' => admin_name, 'attributes' => { 'omejdn' => 'admin' } })
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
    Dir.mkdir CONFIG_DIR unless File.directory? CONFIG_DIR
    file = File.new "#{CONFIG_DIR}/#{section}.yml", File::CREAT | File::TRUNC | File::RDWR
    file.write data.to_yaml
    file.close
  end

  def self.read_config(bind)
    section = bind.local_variable_get :section
    return unless File.exist?(filename = "#{CONFIG_DIR}/#{section}.yml")

    YAML.safe_load (File.read filename), filename: filename
  end

  # register functions
  def self.register
    PluginLoader.register 'CONFIGURATION_STORE', method(:write_config)
    PluginLoader.register 'CONFIGURATION_LOAD',  method(:read_config)
  end
end
