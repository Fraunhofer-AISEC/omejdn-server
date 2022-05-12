# Omejdn Plugins

Omejdn provides a mechanism for extending its functionality with plugins.
Plugins are pieces of Ruby code which are executed when so-called events are fired,
and may make arbitrary changes to the program's state.

There are three types of plugins:

* **Default Plugins** are plugins that implement necessary but interchangable behavior.
  Examples include the `DefaultUserDB` which provides a way of storing
  users.
  You have to explicitly disable them if you want to replace their
  functionality.
  They are found in Omejdn's Core code in `/lib`.

* **Official Plugins** live in the same repository as Omejdn and can be found in `/plugins`.
  They offer functionality that can be considered useful in a diverse range of use cases.
  Optional OAuth/OpenID functionality is implemented in plugins if it is not near-universally useful.
  Examples include the `federation` plugin which allows to delegate identity management.

* **Custom Plugins** are not part of this repository and typically involve functionality
  specific to a particular setup (e.g. a custom user database).
  To use them, they need to be copied to `/plugins` (or simply mounted in container environments).
  Custom Plugins that become useful to a diverse audience can become Official Plugins.
  Please open a corresponding Pull Request at the official Omejdn repository.

## Activating Plugins

Plugins can be activated and configured by specifying them in a YAML file
and instructing Omejdn to load it.
The latter can be done by setting the environment variable `OMEJDN_PLUGINS`.


The following example file activates two plugins called `user_backend_sqlite` and `admin_api`,
configures the former to use a `location` property of `config/users.yml`,
and deactivates the DefaultUserDB plugin.
How plugins use their configuration values is up to the individual plugins
and *should* be documented.

```yaml
deactivate_defaults:
- user
plugins:
  user_backend_sqlite:
    location: config/users.yml
  admin_api:
```

Each explicitly activated plugin lives in a folder corresponding to its name in `/plugins`.
The main Ruby file must have the same name as the plugin.

For example: The main plugin file for the `admin_api` plugin
is located at `/plugins/admin_api/admin_api.rb`.

## Writing Plugins

Plugin main files are loaded and executed upon startup.
You may *require* other files as approproate.
The files are executed on the top-level,
which implies that you have access to the full functionality that Omejdn
and its dependencies provide.

For example, you can register endpoints using Omejdn's `endpoint` function
and have access to the user's `session` hash for storing session data.

You can also register functions to be executed whenever a certain *Event* is fired.
An example event is `TOKEN_CREATED_ACCESS_TOKEN`,
which is fired whenever Omejdn creates an access token.
You then have the option to hook into the code and e.g. modify the token.
See [Events](./Events.md) for a listing of all available events.

The following code demonstrates how to subscribe to a certain event:

```ruby
def my_awesome_function(bind)
    # This is called every time the TOKEN_CREATED_ACCESS_TOKEN event is fired
end

PluginLoader.register('TOKEN_CREATED_ACCESS_TOKEN', :my_awesome_function)
```

The registered function is called with a single argument: The binding of the caller.
This binding allows you to modify the caller's environment.
For example, to get a local variable `var`, you can use

```ruby
var = bind.local_variable_get(:var)
```

To set a local variable `var` to `5`, you can use

```ruby
bind.local_variable_set(:var, 5)
```

Please have a look at the Ruby documentation for more information on bindings.

### Best Practice for writing plugins

When writing plugins, try to keep it compatible with other plugins.
In particular, you should avoid cluttering the top-level with symbols
such as helper functions that may conflict with functionality in other plugins.

Always try to use functionality that is already provided by Omejdn
rather than implementing it yourself.

Ruby bindings provide a method called `eval` executing arbitrary code given as a string.
Be extremely cautious when using it and make sure to sanitize any inputs to avoid
arbitrary code execution exploits.
