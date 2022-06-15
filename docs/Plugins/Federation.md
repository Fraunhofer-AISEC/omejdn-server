# Authentication Federation

This Plugin allows to federate authorization decisions to other OpenID Providers (OPs).
Supported are conventional OPs as well as Self-Issued OPs as per the SIOPv2 draft.
The executed flow is the authorization code flow where possible.
For SIOPs, the implicit flow is supported as well.

Currently, the plugin allows anyone to log in that can log in at the federated OP.
For SIOPs, this is everyone!
However, the plugin allows to add custom functionality to determine the attribute set of any user.
This can be used for access control.

Configuration comes in two parts:

1. Provider Configuration determines the OPs which are given as an option to log in
1. Attribute Mappers determine the attributes mapped to foreign users

Currently, only static configuration is available.
A full configuration (including all optional parameters) looks like this:

```yaml
plugins:
  federation:
    providers:
      myawesomeop:
        issuer: https://example.org/auth
        metadata:
          insertMetadata: here
        self-issued: false
        description: Login with My Awesome OP
        op_logo_uri: https://example.org/logo.png
        token_endpoint_auth_method: client_secret_basic
        client_id: myAwesomeClientID
        client_secret: myAwesomeClientSecret
        scope:
        - openid
        - profile
        attribute_mappers:
        - mycustommapper
    attribute_mappers:
      mycustommapper:
        type: static
        prerequisites:
          sub:
          - user01
          - user02
        attributes:
          - key: omejdn
            value: read
```

## Provider Configuration

Every OP has a unique identifier `:id` and a configuration found under `plugins.federation.:id`.
The configuration options in detail are presented below:

### Issuer Identifier and OP Server Metadata

An OP is a SIOP iff `self-issued` is given and set to true.

Unless the OP is a SIOP, an Issuer Identifier `issuer` MUST be specified.
This issuer identifier is also used to find the relevant metadata document according to RFC 8414 or OIDC Discovery,
unless the metadata document is explicitly given as `metadata`.

If the OP is a SIOP, then the precedence for determining the metadata document is as follows:

- If `metadata` is given, it is used as the metadata document
- If `issuer` is given, it is resolved according to RFC 8414 and OIDC Discovery
- The SIOP static discovery metadata document is used

### OP Selection Attributes

When the user is asked to log in, they is presented with an option for each OP.
The option shows (in order of highest to lowest precedence):

- An image found at the URL given by `op_logo_uri`
- The text given by `description`
- The text "Login with `:id`"

### OIDC Parameters

The array given as `scope` is used to determine the scopes to request.

Unless the OP is a SIOP and on-demand registration is to be performed,
the values `token_endpoint_auth_method` and `client_id` have to be provided.

The following authentication methods are supported:

- `none`
- `client_secret_basic` (requires specifying a `client_secret`)
- `client_secret_post` (requires specifying a `client_secret`)
- `private_key_jwt`

Be aware that `private_key_jwt` is only available for non-SIOPs and uses Omejdn's usual signing keys.
You may want to register Omejdn's `jwks_uri` at the OP when using this method.

### Attribute Mappers

A list of `attribute_mappers` SHOULD also be specified.
Each one determines the name of an attribute mapper to apply when generating users from this OP.

## Attribute Mapper Configuration

Each attribute mapper has a unique `:name`, and a configuration found under `plugins.attribute_mappers.:id`.

It MUST specify a `type`, which determines the procedure by which attributes are added.
While you may write your own attribute mapper types,
the default types are as follows:

- `static` maps the specified `attributes` to every user. Example configuration:

```yaml
staticmapper:
  type: static
  attributes:
    - key: omejdn
      value: read
```

- `clone` copies attribute values from id token claims to keys specified in the `mapping`. Example Configuration:

```yaml
clonemapper:
  type: clone
  mapping:
    - from: sub
      to: external_sub
```

Each attribute mapper may additionally specify some `prerequisites` for it to apply.
These are a list of key-value pairs which are satisfied iff at least one of the specified values appears under the specified key in the userinfo.
This is most useful for OPs that list the user's groups in the userinfo.

## Writing Custom Mapper Types

Other plugins may write their own mapper types to support more complex behaviour.

To implement a new type `:type`, simply register for the event `PLUGIN_FEDERATION_ATTRIBUTE_MAPPING_:TYPE`,
where `:TYPE` is the uppercased `:type`.
The call should return an array of attributes you would like to add to a user.
The configuration for your type can be found via the binding in a local variable `mapper`,
and the userinfo in the local variable `userinfo`.
