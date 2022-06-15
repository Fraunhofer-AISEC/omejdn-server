# Postgres Storage Backend

The official `postgres_backend` plugin provides the means to store Omejdn's data
in a persistent storage backend,
thanks to the magic of Postgres.

## Configuration

Since any configuration is stored inside this plugin,
there is no dynamic configuration.
An example static configuration to activate the plugin looks like this:

```yaml
plugins:
   postgres_backend:
      connection:
         host: localhost
         port: 5432
         dbname: omejdn
         user: myuser
         password: mypassword
      handlers:
         - keys
         - config
         - client
         - user
deactivate_defaults:
   - config
   - keys
   - client
   - user
```

The plugin can replace the default plugins.
Therefore you want to specify all activated handlers in `deactivate_defaults`,
so Omejdn does not use more than one backend.
It is still possible to leave the default `user` and `client` DBs active.
In this case, do not forget to set a `user_backend_default` and
`client_backend_default` in the configuration,
so Omejdn knows which plugin to use for new users and clients.


The configuration options in detail:

- **connection** specifies the connection to the Postgres instance.
  You may use any of the values defined [here](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-PARAMKEYWORDS).
  A few intuitive options are given in the example above.
- **handlers** specifies a list of handlers to register.
  The full list is shown in the example above.
  If you omitt this option, the default is to register all event handlers.

## Database Layout

If you would like to manipulate the database yourself, you can do so.
The following overview of where to find what should get you started.

- Users are saved with username and (hashed) password in `users`
- Clients have their metadata stored in `clients`
- Both Users and Clients can have attributes.
  These are saved in `attributes`
- Cryptographic keys and certificates are stored in `keys`.
  A type of `sk` indicates a private key, while `certs` are certificate chains.
- For each configuration section, there is a separate relation in the database
  named `configuration_<section>`.
  The main configuration e.g. can be found in `configuration_omejdn`.
