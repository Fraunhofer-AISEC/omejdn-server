# Omejdn Plugins

You can add your own plugins in the corresponding folder.

Omejdn supports the following types of plugins:

* **user_db**: Storage backends for users
* **claim_mapper**: Mapping claims from and to user/client attributes
* **api**: Additional Endpoints and APIs

Plugins can be activated by specifying them in `omejdn.yml`:

```yaml
plugins:
  user_db:
    yaml:
    ldap:
  api:
    selfservice:
    admin:
```

Plugin files are loaded upon startup. To be able to call their functionality,
Claim Mapper and User DB plugins must return an appropriate class through a function `load_{type}_{name}` in the `PluginLoader`.
It takes one argument: The configuration from the Configuration file,
which the plugin should supplement by reasonable default values.
Here is an example from the LDAP User DB Plugin:

```ruby
class PluginLoader
  def self.load_user_db_ldap(config)
    LdapUserDb.new config
  end
end
```

The corresponding abstract class can be found in the file `_abstract.rb`.
You might want to include it in your plugin like so:

```ruby
require_relative './_abstract'
```

Likewise, if your plugin depends on other plugins, you should require them.
