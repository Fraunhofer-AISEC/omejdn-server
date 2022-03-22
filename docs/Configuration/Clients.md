# Client Configuration

Clients are configured in `config/clients.yml`.
The YAML-File contains an Array of clients, each of which has a range of properties.
A minimal example for a public client looks like this:

```
- client_id: exampleClient
  token_endpoint_auth_method: none
  redirect_uris: https://example.org/callback
  scope: openid
```

The recognized properties of each client are the values specified in RFC 7591,
along with the claim `resource` for specifying requestable `resource` parameters,
and `attributes` for specifying custom user attributes on clients.

The claims `jwks` and `jwks_uri` are currently ignored.
Instead, X.509 Certificates may be imported into Omejdn using the claim `import_certfile`.
See [Keys](./Keys.md) for more information on client certificates.

Additional metadata claims are retained, and future versions of Omejdn may use these values.

Metadata consisting of an Array of Strings may be specified as a single string,
if only one value is to be specified.

## Client Identifier

```
client_id: exampleClient
```

The unique identifier for the client.
This claim is required and must be known to the client.
For RFC 6749 compliance, it may only include printable ASCII characters.

## Information about the client

All claims in this section are optional, but most are shown to the user during Authorization.

```
client_name: Awesome App
```

A human-readable name for the client.

```
client_uri: https://example.org/about
```

A URL leading to more information about the client.

```
logo_uri: https://example.org/logo.png
```

A URL to a logo. The logo may be in any format, but formats recognized by modern browsers are recommended.

```
tos_uri: https://example.org/terms
```

A URL to the client's Terms of Service.

```
policy_uri: https://example.org/privacy
```

A URL to the client's Privacy Policy.

```
software_id: AwesomeApp
software_version: 1.0.0
```

The software and version used by the client.

```
contacts:
- John Doe, Fraunhofer AISEC
- issue@example.org
```

Contacts for the server operator in case of problems.

## Client Authentication

```
token_endpoint_auth_method: private_key_jwt
```

The authentication method the client will use at all directly accessed endpoints
(such as `/token` and `/par`).
Supported values include:

- `none`
- `client_secret_basic`
- `client_secret_post`
- `private_key_jwt`

Clients that run at the end user (such as browser applications) should use the `none` method.
These are referred to as public clients.
Clients that are able to guard secrets should preferrably use the `private_key_jwt` method, or any of the `client_secret` methods, if the former is unsupported.
These are referred to as confidential clients.

For setting up the keys for clients authenticating via `private_key_jwt`, please have a look at [Keys](./Keys.md).

```
client_secret: supersecret
```

A client secret for the `client_secret_basic` and `client_secret_post` client authentication methods.

## Authorization Grant Options

```
grant_types:
- authorization_code
- client_credentials
```

A list of permissible grant types to be used by a client at the `/token` endpoint.

```
redirect_uris:
- https://example.org/callback01
- https://example.org/callback02
```

A list of valid redirect URIs for a client to be used during authorization code flows.
If the client may not use the `authorization_code` grant, this value is not used.

```
post_logout_redirect_uris:
- https://example.org/callback01
- https://example.org/callback02
```

A list of valid redirect URIs for a client to be used after logging out users.

```
request_uris:
- https://example.org/request01
- https://example.org/request02
```

A list of valid request URIs for a client to be used in authorization code flows.

## Authorization Scope

```
scope: [omejdn:write,openid]
```

A whitelist of scopes the client may request via the `/token` and `/authorize` endpoints.
Note that `openid` has to be explicitly included for OpenID clients.

```
resource: [http://example.org]
```

A whitelist of resources the client may request.
If unspecified, a client may request arbitrary resources.

*Note: To access the Omejdn API and userinfo endpoints, the allowed resources should include the Omejdn `front_url` specified in `omejdn.yml` concatenated with `/api` and `/userinfo` respectively.*

If the default audience specified in `omejdn.yml` is not included, a client MUST explicitly request resources contained in this list.

## Client Attributes

```
attributes:
  - key: omejdn
  - value: admin
```

A list of attributes. Each attribute can have the following parameters:

- `key` the parameter name
- `value` a default value
- `dynamic` set this to true to allow requesting a value in the claims parameter when requesting a token.

Scopes of the form `a:b` may be granted for a client only if said client has an attribute with key `a` and value `b`,
while scopes of the form `a` can be granted as long as an attribute with key `a` exists.