# Events

These are the events that are emitted by Omejdn.
You may hook into any one of them by using

```ruby
def event_handler(bind)
    # Edit the binding context
    # E.g. using bind.local_variable_get(:var)
    # or bind.local_variable_set(:var)
end

PluginLoader.register('<desired_event>', :event_handler)
```

The event_handler will be called every time Omejdn comes across

```ruby
PluginLoader.fire('<desired_event>', binding)
```

This allows you to directly edit any values in the caller's context.

## Core Events

### TOKEN_CREATED_ACCESS_TOKEN

Fired once the core access token is created.
You may edit the token using the local variable `token`.

### TOKEN_CREATED_ID_TOKEN

Fired once the core id token is created.
You may edit the token using the local variable `token`.

### USER_GET

Fired to retrieve a certain user.
Should return a user or nil if not found.
The `username` local variable holds the username to search for.
The `@backend` should be set for each such user.

### USER_GET_ALL

Fired to retrieve all users.
Should return an array of users the plugin is storing.
The `@backend` should be set for each such user.

### USER_CREATE

### USER_UPDATE

### USER_DELETE

### USER_AUTHENTICATION_PASSWORD_CHANGE

Fired when trying to update a password for a user.
Use the user (`self`) and the local variable `pass` to return `true` if the password was correct and `false` otherwise.

The call should return nil unless the user is stored behind the plugin.
Use the `@backend` to check!

### USER_AUTHENTICATION_PASSWORD_VERIFY

Fired upon receiving a password for a user.
Use the user (`self`) and the local variable `pass` to return `true` if the password was correct and `false` otherwise.

The call should return nil unless the user is stored behind the plugin.
Use the `@backend` to check!

## Plugin Events

Plugins may define their own events and call them when appropriate.
These Events should follow the naming convention `PLUGIN_<pluginname>_<eventname>`, with everything capitalized.