# frozen_string_literal: true

def map_attributes_static(bind)
  config = bind.local_variable_get 'mapper'
  config['attributes']
end
PluginLoader.register 'PLUGIN_FEDERATION_ATTRIBUTE_MAPPING_STATIC', method(:map_attributes_static)

def map_attributes_clone(bind)
  config = bind.local_variable_get 'mapper'
  userinfo = bind.local_variable_get 'userinfo'
  attrs = (config['mapping'] || {}).map do |map|
    {
      'key' => map['to'],
      'value' => userinfo[map['from']]
    }
  end
  attrs.reject { |a| a['key'].nil? }
end
PluginLoader.register 'PLUGIN_FEDERATION_ATTRIBUTE_MAPPING_CLONE', method(:map_attributes_clone)
