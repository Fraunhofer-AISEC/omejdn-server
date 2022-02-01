# frozen_string_literal: true

require 'socket'
require 'net/ldap'
require 'base64'

# LDAP User DB backend
class LdapUserDb < UserDb
  @dn_cache = {}

  def decode_value(value, encoding)
    begin
      ret = Base64.strict_decode64(value).force_encoding(encoding)
      return ret if ret.valid_encoding?
    rescue StandardError
      puts 'Failed to decode, interpret as plain text'
    end
    value
  end

  def ldap_entry_to_user(entry)
    user = {
      'username' => entry.dig(Config.user_backend_config.dig('ldap', 'uidKey'), 0),
      'password' => nil,
      'extern' => true,
      'backend' => 'ldap'
    }
    user['attributes'] = []
    entry.each do |key, value|
      user['attributes'] += case key
                            when :l
                              [{ 'key' => 'locality',       'value' => decode_value(value[0], 'utf-8') }]
                            when :postalcode
                              [{ 'key' => 'postal_code',    'value' => decode_value(value[0], 'ascii') }]
                            when :street
                              [{ 'key' => 'street_address', 'value' => decode_value(value[0], 'utf-8') }]
                            when :sn
                              [{ 'key' => 'family_name',    'value' => decode_value(value[0], 'utf-8') }]
                            when :givenname
                              [{ 'key' => 'given_name',     'value' => decode_value(value[0], 'utf-8') }]
                            when :telephonenumber
                              [{ 'key' => 'phone_number',   'value' => decode_value(value[0], 'ascii') },
                               { 'key' => 'phone_number_verified', 'value' => true }]
                            when :mail
                              [{ 'key' => 'email',          'value' => decode_value(value[0], 'utf-8') },
                               { 'key' => 'email_verified', 'value' => true }]
                            end
    end
    user['attributes'].compact!
    User.from_dict user
  end

  def all_users
    config = Config.user_backend_config
    ldap = connect_directory(config)
    t_users = []
    ldap.search do |entry|
      user = ldap_entry_to_user(entry)
      t_users << user unless user.nil?
    end
    t_users
  end

  def lookup_user(username, config)
    return @dn_cache[username] unless @dnCache[username].nil?

    dir = connect_directory(config)
    dir.search(filter: Net::LDAP::Filter.eq(config.dig('ldap', 'uidKey'), username)) do |entry|
      return entry.dn
    end
    nil
  end

  def verify_password(user, password)
    config = Config.user_backend_config
    user_dn = lookup_user(user.username, config) if user_dn.nil?
    return false if user_dn.nil?

    !connect_directory(config, user_dn, password).nil?
  end

  def connect_directory(config, bind_dn = nil, bind_pass = nil)
    if bind_dn.nil?
      bind_dn   = ENV['OMEJDN_LDAP_BIND_DN']
      bind_pass = ENV['OMEJDN_LDAP_BIND_PW']
    end
    ldap_conf = {
      host: config.dig('ldap', 'host'),
      port: config.dig('ldap', 'port'),
      base: config.dig('ldap', 'baseDN'),
      verbose: true,
      encryption: {
        method: :simple_tls,
        tls_options: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
      }
    }
    if bind_dn
      ldap_conf[:auth] = {
        method: :simple,
        username: bind_dn,
        password: bind_pass
      }
    end

    dir = Net::LDAP.new(ldap_conf)
    return nil if bind_dn && !dir.bind

    dir
  end

  def find_by_id(username)
    config = Config.user_backend_config
    ldap = connect_directory(config)
    uid_key = config.dig('ldap', 'uidKey')
    filter = Net::LDAP::Filter.eq(uid_key, username)
    ldap.search(filter: filter) do |entry|
      puts "DN: #{entry.dn}"
      @dn_cache[username] = entry.dn
      return ldap_entry_to_user(entry)
    end
    nil
  end
end

# Monkey patch the loader
class UserDbLoader
  def self.load_ldap_db
    LdapUserDb.new
  end
end
