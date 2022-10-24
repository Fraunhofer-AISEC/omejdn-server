# frozen_string_literal: true

source 'https://rubygems.org'

# Necessary Gems for Core Omejdn
group :omejdn do
  gem 'bcrypt'
  gem 'haml'
  gem 'jwt', git: 'https://github.com/jwt/ruby-jwt.git'
  gem 'sinatra'
  gem 'sinatra-contrib'
  gem 'thin'
end

# Necessary Gems for Plugins
group :plugins do
  gem 'json-schema'
  gem 'net-ldap'
  gem 'pg'
  gem 'rqrcode'
end

# Development only
group :development do
  gem 'rack-test'
  gem 'rubocop'
  gem 'test-unit'
end
