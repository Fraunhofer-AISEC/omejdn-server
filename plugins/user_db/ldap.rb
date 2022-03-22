# frozen_string_literal: true

require 'socket'
require 'net/ldap'
require 'base64'
require_relative './_abstract'

# LDAP User DB backend
class LdapUserDb < UserDb
  attr_reader :config

  @dn_cache = {}

  def initialize(config)
    super()
    @config = {
      'host' => 'localhost',
      'port' => 636,
      'base_dn' => '',
      'uid_key' => 'dn'
    }.merge(config || {})
  end

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
      'username' => entry.dig(@config['uid_key'], 0),
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
    ldap = connect_directory
    t_users = []
    ldap.search do |entry|
      user = ldap_entry_to_user(entry)
      t_users << user unless user.nil?
    end
    t_users
  end

  def lookup_user(username)
    return @dn_cache[username] unless @dnCache[username].nil?

    dir = connect_directory
    dir.search(filter: Net::LDAP::Filter.eq(@config['uid_key'], username)) do |entry|
      return entry.dn
    end
    nil
  end

  def verify_password(user, password)
    user_dn = lookup_user(user.username) if user_dn.nil?
    return false if user_dn.nil?

    !connect_directory(user_dn, password).nil?
  end

  def connect_directory(bind_dn = nil, bind_pass = nil)
    if bind_dn.nil?
      bind_dn   = ENV['OMEJDN_LDAP_BIND_DN']
      bind_pass = ENV['OMEJDN_LDAP_BIND_PW']
    end
    ldap_conf = {
      host: @config['host'],
      port: @config['port'],
      base: @config['base_dn'],
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
    ldap = connect_directory
    uid_key = @config['uidKey']
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
class PluginLoader
  def self.load_user_db_ldap
    LdapUserDb.new
  end
end
