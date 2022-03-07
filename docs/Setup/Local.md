# Basic local Setup

Starting Omejdn just involves navigating to Omejdn's root directory
and executing the following commands:

```
$ bundle install
$ ruby omejdn.rb
```

This will result in a plain OAuth 2.0/2.1 authorization server
with no configured clients or users, available at `http://localhost:4567`.

## Configuration

In most circumstances, the above is not what the use-case demands.
Hence, you need to configure Omejdn to your use case.
The documentation you are reading provides a great deal of information on 
Omejdn's Configuration in the [Configuration Folder](<../Configuration/Main Configuration.md>).
The following is a tour of the most used features of Omejdn
that leave you with a mostly OpenID compliant setup
(Note that full compliance requires, among other things, the use of TLS.
See [Production](./Production.md)).

### Editing Server settings

The main configuration file is `config/omejdn.yml`.
It is documented [here](<../Configuration/Main Configuration.md>).

At a minimum, you probably want to configure the following options.
Note that some other default values filled in when first starting Omejdn are based on these,
so it is suggested to start with a new configuration file,
edit these values and let Omejdn fill in the rest for you,
unless you have read the Main Config documentation.

- `issuer` should be the desired URL to reach Omejdn
- `openid` can be set to true to enable OpenID specific functionality
- `plugins/user_db` should contain at least one User Database Plugin.
For most simple use cases, the `YAML` plugin should suffice.

### Adding clients

Clients are configured in `config/clients.yml`.
The file is documented [here](../Configuration/Clients.md).

A minimal client capable of using the OpenID authorization flow looks like this:

```
- client_id: myClient
  token_endpoint_auth_method: none
  redirect_uris: http://localhost
  scope:
  - openid
  - profile
```

### Adding users

How to add a user depends on the user database plugin in use.
We are going to use the `YAML` plugin.

Edit the file specified as `location` for the `YAML` plugin
(`config/users.yml` by default).

A user looks like this:

```
- username: testuser
  password: <password>
  attributes:
  - key: preferred_username
    value: testy
```

While passwords may be specified as plaintext,
it is *strongly* recommended to instead specify the salted hashes generated like so:

```
$ ruby -rbcrypt -e 'puts BCrypt::Password.create("testpassword")'
```

### Mapping Scopes

Scopes are described in detail in [Scopes](../Configuration/Scopes.md).

For an OpenID setup, the default configuration suffices,
but in general you should map your scopes to the relevant user attribute keys
in `config/scope_mapping.yml`.

### Starting the authorization Flow

This is usually done by any OAuth 2.0 or OpenID client library.

If you want to do it manually, have a look at [Authorization Flow](<../Usage/Authorization Flow.md>).