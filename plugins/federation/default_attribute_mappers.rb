# frozen_string_literal: true

def map_attributes_static(bind)
  config = bind.local_variable_get 'mapper'
  attributes = bind.local_variable_get 'attributes'
  attributes.merge!(config['attributes'] || {})
end
PluginLoader.register 'PLUGIN_FEDERATION_ATTRIBUTE_MAPPING_STATIC', method(:map_attributes_static)

def map_attributes_clone(bind)
  config = bind.local_variable_get 'mapper'
  userinfo = bind.local_variable_get 'userinfo'
  attributes = bind.local_variable_get 'attributes'
  (config['mapping'] || {}).each do |map|
    attributes[map['to']] = { 'value' => userinfo[map['from']] }
  end
end
PluginLoader.register 'PLUGIN_FEDERATION_ATTRIBUTE_MAPPING_CLONE', method(:map_attributes_clone)
