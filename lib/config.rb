# frozen_string_literal: true

require 'yaml'

OMEJDN_BASE_CONFIG_FILE = 'config/omejdn.yml'
OMEJDN_USER_CONFIG_FILE = 'config/users.yml'
OMEJDN_CLIENT_CONFIG_FILE = 'config/clients.yml'
OMEJDN_USER_BACKEND_CONFIG = 'config/user_backend.yml'
OMEJDN_OAUTH_PROVIDER_CONFIG = 'config/oauth_providers.yml'
SCOPE_DESCRIPTION_CONFIG = 'config/scope_description.yml'
SCOPE_MAPPING_CONFIG = 'config/scope_mapping.yml'
WEBFINGER_CONFIG = 'config/webfinger.yml'

# Configuration helpers functions
class Config
  def self.write_config(file, data)
    file = File.new file, File::CREAT | File::TRUNC | File::RDWR
    file.write data
    file.close
  end

  def self.client_config
    YAML.safe_load File.read OMEJDN_CLIENT_CONFIG_FILE, fallback: []
  end

  def self.client_config=(clients)
    clients_yaml = clients.map(&:to_dict)
    write_config(OMEJDN_CLIENT_CONFIG_FILE, clients_yaml.to_yaml)
  end

  def self.base_config
    YAML.safe_load File.read OMEJDN_BASE_CONFIG_FILE
  end

  def self.base_config=(config)
    # Make sure those are integers
    config['token']['expiration'] = config['token']['expiration'].to_i
    config['id_token']['expiration'] = config['id_token']['expiration'].to_i if config['id_token'] && config['id_token']['expiration']
    write_config OMEJDN_BASE_CONFIG_FILE, config.to_yaml
  end

  def self.user_backend_config
    YAML.safe_load File.read OMEJDN_USER_BACKEND_CONFIG, fallback: {}
  end

  def self.user_backend_config=(config)
    write_config OMEJDN_USER_BACKEND_CONFIG, config.to_yaml
  end

  def self.oauth_provider_config
    YAML.safe_load File.read OMEJDN_OAUTH_PROVIDER_CONFIG, fallback: []
  end

  def self.oauth_provider_config=(providers)
    write_config(OMEJDN_OAUTH_PROVIDER_CONFIG, providers.to_yaml)
  end

  def self.scope_description_config
    YAML.safe_load File.read SCOPE_DESCRIPTION_CONFIG, fallback: {}
  end

  def self.scope_mapping_config
    YAML.safe_load File.read SCOPE_MAPPING_CONFIG, fallback: {}
  end

  def self.webfinger_config
    YAML.safe_load File.read WEBFINGER_CONFIG, fallback: {}
  end

  def self.webfinger_config=(config)
    write_config(WEBFINGER_CONFIG, config.to_yaml)
  end
end
