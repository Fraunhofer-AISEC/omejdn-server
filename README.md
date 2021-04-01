# Omejdn _(Bavarian for "Log in")_

Omejdn is an OAuth2/OpenID connect server for ...

  1. IoT devices which use their private keys to request OAuth2 access tokens in order to access protected resources
  2. Websites or apps which retrieve user attributes

It is used as the _Dynamic Attribute Provisioning Service (DAPS)_ prototype of
the [Industrial Data Space](https://industrial-data-space.github.io/trusted-connector-documentation/).

**IMPORTANT**: Omejdn is meant to be a research sandbox in which we can
(re)implement standard protocols and potentially extend and modify functionality
under the hood to support research projects.
It is **NOT** a production grade solution and should not be used as such.

## Table of Contents

- [Supported Standards](#spec)
- [Running an Omejdn server](#running)
- [Configuring the server](#config)
- [Requesting an access token](#req)


<a name="spec"/>

## Supported Standards

This server implements:

  - [RFC7523 JWT bearer client authentication](https://tools.ietf.org/html/rfc7523#section-2.2) for [OAuth2](https://tools.ietf.org/html/rfc6749).
  - [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) with [discovery support](https://openid.net/specs/openid-connect-discovery-1_0.html) and [dynamic client registration](https://openid.net/specs/openid-connect-registration-1_0.html)

**NOTE**: Omejdn only implements *two* grant types:

  - `client_credentials` for RFC7523.
  - `authorization_code` for OpenID Connect.

In particular, it does *not* implement the [JWT bearer authorization grant](https://tools.ietf.org/html/rfc7523#section-2.1)
or the [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2).

The *only* OpenID Connect authorization flow supported is the authorization code
flow (with or without [PKCE](https://tools.ietf.org/html/rfc7636)).
As specified in the
[OAuth2 Security Best Current Practice Document](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-14),
these are the only grant types we will likely support for OAuth2.0 and OpenID Connect.


<a name="running"/>

## Running an Omejdn server

### Run with docker

By default, omejdn uses the following directory structure for configurations and keys:

    /opt
      | config/
      |   \_ omejdn.yml
      |   \_ user_backend.yml
      |   \_ clients.yml
      |   \_ users.yml
      |   \_ webfinger.yml
      |   \_ oauth_providers.yml
      |   \_ scope_description.yml
      |   \_ scope_mapping.yml
      \ keys/
          \_ signing_key.pem (The OAuth2 server RSA private key)
          \_ <Base64(clientID1)>.cert (The public key certificate for clientID1)
          \_ <Base64(clientID2)>.cert
          \_   ...

It is recommended, that you create the directories *config/* and *keys/* locally and mount them using docker:

    $ mkdir config
    $ mkdir keys
    $ docker run -d  --name=omejdn -p 4567:4567 -v $PWD/config:/opt/config -v $PWD/keys:/opt/keys <dockerimage>

You should provide the config files in *config/* and can use the templates in this repo.

**NOTE**: The server private key  will be generated if it does not exist, but you can also provide your own.


<a name="config"/>

## Configuring the server

### Adding a client

First, you need to create a public/private RSA key pair and a X.509 certificate.
Then, add the public key certificate to omejdn:

    $ cp path/to/your/public/x509.cert keys/<Base64(clientID)>.cert

Now you need to add your client ***clientID*** to the config file
`config/clients.yml`:

    - clientID:
      name: My Clienti
      redirect_uri: <uri> (optional, required for OIDC)
      allowed_scopes:
        - <scope1>
        - <scope2>
        - ...
      attributes:
        - key: Attribute1-name
          value: Attribute1-value (single value or array)
        - key: Attribute2-name
          value: Attribute2-value (single value or array)


### Adding a user

Users are added by editing `config/users.yml`. Passwords are stored in the
bcrypt format. Scopes which can be granted by the user must be explicitly
defined.
 If you define an attribute for a scope in `config/scope_mapping.yml`, the
resulting access token (and ID token) will also include this attribute.

### Scopes

A client can request any subset of scopes in the scopes list when requesting a
token. If you define an attribute for a scope in `config/scope_mapping.yml`, the
resulting access token (and ID token) will also include this attribute.
In `config/scope_description.yml` you can configure a short description string
which is displayed to the user in an OpenID Connect flow upon requesting
authorization.

There are some special scopes you may want to use:

  - `openid`: This scope is required if the client shall be able to initia an openid flow.
  - `omejdn:api`: This scope is required if you need to access the omejdn API.
  - `omejdn:admin`: This scope is required if you need to access the omejdn API admin functions.

You can define any allowed client scopes directly in the client configuration.
Please note that the user also needs to have the scopes configured in order to
request them.

<a name="req"/>

## Requesting an access token (RFC7523)

To request an access token, you need to generate a JWT Bearer token as per
[RFC7523](https://tools.ietf.org/html/rfc7523#section-2.2).
You may use the script `create_test_token.rb` to generate a JWT Bearer token
with your private key.
**Note**: You need to generate the respective private key yourself. It is not
part of this repo.

An example of a request using the preconfigured client `testClient` against
omejdn to receive an access token looks like this:

```
    $ curl localhost:4567/token --data "grant_type=client_credentials
                                        &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
                                        &client_assertion=eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJkZW1vY29ubmVjdG9yMSIsInN1YiI6ImRlbW9jb25uZWN0b3IxIiwiZXh
                                                          wIjoxNTQ4Nzg1Mzg2LCJuYmYiOjE1NDg3ODE3ODYsImlhdCI6MTU0ODc4MTc4NiwiYXVkIjoiaHR0cHM6Ly9hcGk
                                                          ubG9jYWxob3N0In0.JSQuMf-9Fd7DNna_-s-sR7eXgcSYNCau5WgurrGJTuCSLKqhZe3odXfunN2vRFgUhU21ADF
                                                          lEq96mlbQDueBlMtaXrcHFPSpIUtvuIMIVqQcGYkDdSJr_VmDuAykCYpyTCkLa7a8DTV-N3sECp-AxUgmEzYIfh8
                                                          jW0WS6ehgUzrnpH6t_h_GWXKkNSAg3ERakDc4NY02pBGmiN7bmtLZNt5b4LWALiiFiduC7JbIpx4awOU6skMApmz
                                                          gLnZmmTG20JlJRg6hAqyHEz5Cd4rUgrt0twmpC0Us_CG23KdUF5fWI55dcO2qAVvhNQXpqz7IiPcF7-jgkrx4ouk
                                                          YNY6eHA
                                        &scope=ids_connector security_level"
```

A response looks like this:

```
    {"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZWN1cml0eV9sZXZlb
                     CI6Nywic2NvcGVzIjpbImlkc19jb25uZWN0b3IiLCJzZWN1cml0eV9sZXZ
                     lbCJdLCJhdWQiOiJJRFNfQ29ubmVjdG9yIiwic3ViIjoibXlDbGllbnQxI
                     iwibmJmIjoxNTQ0MTM0NzMxLCJleHAiOjE1NDQxMzgzMzF9.RXvBfka9_o
                     Nn7Pgu8royJY25l0ua9jj9REVZPftmggEZreb0oKfhr1bLk9KxWrcT5r2i
                     svb3GXRONI5zg7S2KZehZK8PQltFQqcbdOOp1Yx0BbJd1ctRiQhCW9kpAo
                     xHylEahniZXblQ3Z2koFxY82cyVZ48YxUo_8Tda98CeiFufj7ZW8msGfnT
                     ac-lwk2yX8hRHoPVSX72GGQWgZGZd9ATubTypLYaqpLuF9hQ5JYk5WKsDq
                     cFoqk7j_RxkdM0Uw7njnLWhi7GU7FZZ0UFQi-R8IAhUpIpSofcFsoVPynU
                     HrjYWB0ANiL-W1kBqXSNCRS9r7SF3ny3LEOVKbuN5g",
      "expires_in":3600,
      "token_type":"bearer"}
```

The access token will include all requested scopes as well as respective attributes.


## Token verification

All tokens are signed by the server. To retrieve the respecting public key you
can use the JSON Web Key Set (https://tools.ietf.org/html/rfc7517, https://auth0.com/docs/jwks)

```
    $ curl <omejdn URL>/.well-known/jwks.json
```

There exist libraries for most frameworks that allow validation of JWTs
access tokens using JWKS.

## OpenID Connect

By default, OpenID Connect is disabled. In order to enable it, you need to
edit `omejdn.yml` and set `openid` to `true`.

### Discovery

You may retrieve the server configuration under

```
    $ curl <omejdn URL>/.well-known/openid-configuration
```

Please do not forget to configure your external hostname in `omejdn.yml` under
`host`.

## Transport Layer Security

This service does *not* include TLS. Omejdn _must_ be served/proxied through a TLS-enabled webserver, such as nginx.
