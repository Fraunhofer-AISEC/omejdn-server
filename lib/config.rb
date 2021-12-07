# frozen_string_literal: true

require 'yaml'
OMEJDN_CONFIG_DIR            = 'config'
OMEJDN_BASE_CONFIG_FILE      = "#{OMEJDN_CONFIG_DIR}/omejdn.yml"
OMEJDN_USER_CONFIG_FILE      = "#{OMEJDN_CONFIG_DIR}/users.yml"
OMEJDN_CLIENT_CONFIG_FILE    = "#{OMEJDN_CONFIG_DIR}/clients.yml"
OMEJDN_USER_BACKEND_CONFIG   = "#{OMEJDN_CONFIG_DIR}/user_backend.yml"
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
    YAML.safe_load (File.read file), fallback: fallback, filename: file
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
    # Make sure those are integers
    config['token']['expiration'] = config['token']['expiration'].to_i
    if config['id_token'] && config['id_token']['expiration']
      config['id_token']['expiration'] =
        config['id_token']['expiration'].to_i
    end
    write_config OMEJDN_BASE_CONFIG_FILE, config.to_yaml
  end

  def self.user_backend_config
    read_config OMEJDN_USER_BACKEND_CONFIG, {}
  end

  def self.user_backend_config=(config)
    write_config OMEJDN_USER_BACKEND_CONFIG, config.to_yaml
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
end
