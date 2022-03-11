# Omejdn Main Configuration File

Omejdn's main configuration file is located at `config/omejdn.yaml`.
It is a YAML-Formatted configuration file consisting of several configurable options.
It is being reloaded whenever Omejdn needs values from it.
Note however that some changes in values require a restart of Omejdn, such as the loading and unloading of Plugins.

*Note: If you omitt any configuration options, Omejdn will fill in reasonable defaults for you. This also means that any comments in this file will get overwritten*

## Main Configuration Options

### Issuer Identifier

```
issuer: http://example.org
```

Omejdn's OAuth 2.0 Issuer identifier.
It is used as the `iss` value in any issued tokens and advertised as `issuer` in the OAuth Server Metadata.

It is important that, per RFC 8414, the server metadata document is made available
at a URL given by the Issuer Identifier's scheme and authority,
followed by `/.well-known/oauth-authorization-server`, followed by the Issuer Identifier's optional path.
For example, if the Issuer Identifier is `https://example.org/my/path`,
then the URL `https://example.org/.well-known/oauth-authorization-server/my/path` must serve Omejdn's `/.well-known/oauth-authorization-server` endpoint.
For backwards compatibility, the same should be true for the `/.well-known/openid-configuration` infix.
See [NginX](../Integration/NginX.md) for the necessary configuration with NginX.

_Defaults to http://localhost:4567 for testing purposes_

### Front URL

```
issuer: http://example.org/auth
```

The prefix to Omejdn's endpoints.
This is used in several places, the most important one being the OAuth Server Metadata Document,
where e.g. the token endpoint is determined by taking the front URL and appending `/token`.

_Defaults to the `issuer` value_

### Port and Address Binding

```
bind_to: 0.0.0.0/4567
```

An IP address and optional port to bind to.

_Default value: 0.0.0.0/4567_

### Application Environment

```
environment: debug
```
Specifies the level of verbosity for Omejdn.
Can take the following values:

- `production` Do not output debug information
- `development` Be more verbose
- `test` For testing purposes

_Default value: debug_

### Enable OpenID Functionality

```
openid: true
```

This option enables the OpenID connect functionality of Omejdn.
Note that it has to be explicitly enabled.

_Default: false_

### Security Token Settings

```
token:
  expiration: 3600
  algorithm: RS256
id_token:
  expiration: 3600
  algorithm: RS256
```

**Required** Parameters affecting the issued access and ID tokens.
Specified are

- `expiration` The token lifetime in seconds
- `algorithm` The signature algorithm to use.

_Defaults to `3600` for the expiration times and `RS256` for the algorithm_

### Default User Backend

```
user_backend_default: yaml
```

Specifies a plugin to use by default for users created via the Admin API.
Must match one of the enabled User Database Plugins.

_If `openid` is enabled, set to the first specified plugin by default. If not, it is not specified_

### Disable Password Login

```
no_password_login: false
```

Hide the password login when authorizing. Users may still use other Providers. 

_Default: false_

### Default Target Audience

```
default_audience: https://example.org
```

Specifies a default value for the `aud` claim in issued access tokens.
Per RFC 8707, clients may request other values using the `resource` request parameter.
Those other values are granted depending on the client's configuration

_Defaults to ""_

### Accepted Audience Values

```
accept_audience: https://example.org
```

A list of identifiers for which Omejdn is responsible.
When using the `private_key_jwt` or `client_secret_jwt` Client Authentication Methods,
one of the values specified in the `aud` claim has to match one of the values specified here.

_Defaults to the `issuer` value_

## Plugins

Plugins have their own custom configuration, which *should* be documented in the corresponding folder.

In general, the configuration in the configuration file looks like this:

```
plugins:
  user_db:
    yaml:
      location: config/users.yml
  api:
    admin_v1:
    user_selfservice_v1:
      allow_deletion: true
      allow_password_change: true
      editable_attributes:
      - name
  claim_mapper:
    attribute:
```

The Ruby files for the plugins are expected to be found in `plugins/<type>/<name>.rb`,
and they are enabled in the configuration file like this:

```
plugins:
  <type>:
    <name>:
      configuration_option_1: value_1
      configuration_option_2: value_2
```

Different types of plugins are used for different purposes within Omejdn.
Please have a look at the corresponding folder in this documentation.