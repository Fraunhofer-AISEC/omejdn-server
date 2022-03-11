# frozen_string_literal: true

require 'yaml'
OMEJDN_CONFIG_DIR            = 'config'
OMEJDN_BASE_CONFIG_FILE      = "#{OMEJDN_CONFIG_DIR}/omejdn.yml"
OMEJDN_CLIENT_CONFIG_FILE    = "#{OMEJDN_CONFIG_DIR}/clients.yml"
OMEJDN_OAUTH_PROVIDER_CONFIG = "#{OMEJDN_CONFIG_DIR}/oauth_providers.yml"
SCOPE_DESCRIPTION_CONFIG     = "#{OMEJDN_CONFIG_DIR}/scope_description.yml"
SCOPE_MAPPING_CONFIG         = "#{OMEJDN_CONFIG_DIR}/scope_mapping.yml"
WEBFINGER_CONFIG             = "#{OMEJDN_CONFIG_DIR}/webfinger.yml"

# Configuration helpers functions
class Config
  def self.write_config(file, data)
    file = File.new file, File::CREAT | File::TRUNC | File::RDWR
    file.write data
    file.close
  end

  def self.read_config(file, fallback)
    (YAML.safe_load (File.read file), fallback: fallback, filename: file) || fallback
  end

  def self.client_config
    read_config OMEJDN_CLIENT_CONFIG_FILE, []
  end

  def self.client_config=(clients)
    clients_yaml = clients.map(&:to_dict)
    write_config(OMEJDN_CLIENT_CONFIG_FILE, clients_yaml.to_yaml)
  end

  def self.base_config
    read_config OMEJDN_BASE_CONFIG_FILE, {}
  end

  def self.base_config=(config)
    write_config OMEJDN_BASE_CONFIG_FILE, config.to_yaml
  end

  def self.oauth_provider_config
    read_config OMEJDN_OAUTH_PROVIDER_CONFIG, []
  end

  def self.oauth_provider_config=(providers)
    write_config(OMEJDN_OAUTH_PROVIDER_CONFIG, providers.to_yaml)
  end

  def self.scope_description_config
    read_config SCOPE_DESCRIPTION_CONFIG, {}
  end

  def self.scope_mapping_config
    read_config SCOPE_MAPPING_CONFIG, {}
  end

  def self.webfinger_config
    read_config WEBFINGER_CONFIG, {}
  end

  def self.webfinger_config=(config)
    write_config(WEBFINGER_CONFIG, config.to_yaml)
  end

  # Fill missing values in the main configuration
  def self.setup
    config = base_config
    apply_env(config, 'issuer',           'http://localhost:4567')
    apply_env(config, 'front_url',        config['issuer'])
    apply_env(config, 'bind_to',          '0.0.0.0:4567')
    apply_env(config, 'environment',      'development')
    apply_env(config, 'openid',           false)
    apply_env(config, 'default_audience', '')
    apply_env(config, 'accept_audience',  config['issuer'])
    %w[access_token id_token].each do |token|
      apply_env(config, "#{token}.expiration", 3600)
      apply_env(config, "#{token}.algorithm",  'RS256')
    end
    has_user_db_configured = config.dig('plugins', 'user_db') && !config.dig('plugins', 'user_db').empty?
    if ENV['OMEJDN_ADMIN'] && !has_user_db_configured
      # Try to enable yaml plugin, to have at least one user_db
      config['plugins'] ||= {}
      config['plugins']['user_db'] = { 'yaml' => nil }
      has_user_db_configured = true
    end
    if config['openid'] && !has_user_db_configured
      puts 'ERROR: No user_db plugin defined. Cannot serve OpenID functionality'
      exit
    end
    apply_env(config, 'user_backend_default', config.dig('plugins', 'user_db').keys.first) if has_user_db_configured
    Config.base_config = config
  end

  def self.apply_env(config, conf_key, fallback)
    conf_parts = conf_key.split('.')
    env_value = ENV["OMEJDN_#{conf_parts.join('__').upcase}"]
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
      admin = User.from_dict({
                               'username' => admin_name,
                               'attributes' => [{ 'key' => 'omejdn', 'value' => 'admin' }]
                             })
      User.add_user(admin, Config.base_config['user_backend_default'])
    end
    admin.update_password(admin_pw)
  end
end
