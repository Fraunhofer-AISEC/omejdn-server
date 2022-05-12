# Plugin Configuration

You can add customizable behavior to your plugins by specifying configuration options.
These can be specified in one of two ways.

## Static Configuration

When Omejdn is started, it can read YAML files specifying plugins
whose locations are given in the environment variable `OMEJDN_PLUGINS`.
These plugins may come with additional configuration data
available via `PluginLoader.configuration(plugin_name)`
Consider this example `plugins.yml` file:

```yaml
plugins:
  my_awesome_plugin:
    foo: 5
    bar: ["hello"]
```

This loads a plugin from `plugins/my_awesome_plugin/my_awesome_plugin.rb`.
If said plugin calls `PluginLoader.configuration('my_awesome_plugin')`,
it will receive the following hash:

```ruby
{
    'foo' => 5,
    'bar' => ["hello"]
}
```

Static configuration files are only read once and never written to.
If you need to change configuration data,
you might want to consider using dynamic configuration instead
(or in addition to static configuration).

## Dynamic Configuration

Omejdn provides `Config.read_config(section, fallback)` and `Config.write_config(section, data)`,
which you can use to read and write arrays and hashes from and into the configuration store.

By convention, your plugin should use its name as section
and initialize the configuration data with default values right after startup.
This will allow other components to find your configuration data
(Think e.g. about Omejdn's Admin UI).