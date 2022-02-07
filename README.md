# Omejdn _(Bavarian for "Log in")_

[![build-server](https://github.com/Fraunhofer-AISEC/omejdn-server/actions/workflows/build-server.yml/badge.svg)](https://github.com/Fraunhofer-AISEC/omejdn-server/actions/workflows/build-server.yml) ![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/Fraunhofer-AISEC/omejdn-server?sort=semver)

![Omejdn](public/img/logo.jpg)

Omejdn is a minimal but extensible OAuth 2.0/OpenID connect server for ...

1. IoT devices which use their private keys to request OAuth2 access tokens in order to access protected resources
1. Websites or apps which retrieve user attributes

It is used as the _Dynamic Attribute Provisioning Service (DAPS)_ prototype of
the [Industrial Data Space](https://industrial-data-space.github.io/trusted-connector-documentation/).

Some of Omejdn's core features include:

* Database-free easy-to-read configuration files
* Integration of existing LDAP directory services
* Fully configurable through the Admin API Plugin (see API.md)
* A User Selfservice API Plugin


**IMPORTANT**: Omejdn is meant to be a research sandbox in which we can
(re)implement standard protocols and potentially extend and modify functionality
under the hood to support research projects.
It is **NOT** a production grade solution and should not be used as such.

Before updating, please take a look at `release_notes.md` to see if an update requires manual intervention.

---

## Quickstart

The main configuration file is `config/omejdn.yml`.
The default values result in a plain OAuth 2.0 server with no OpenID support
and no way to add users, served at `localhost:4567`

Depending on your use case, you might want to at least configure the following options:

* `issuer` should be the desired URL to reach Omejdn
* `openid` enables OpenID compatibility
* `plugins/user_db` is used to configure storage for users. The `yaml` plugin should be sufficient for a semi-static set of users.

To start Omejdn, simply execute

```
$ bundle install
$ ruby omejdn.rb
```

You may now add clients and users as decribed below, and request access tokens for them.
The token endpoint is `/token` and the authorization endpoint is `/authorize`,
as advertised at `/.well-known/oauth-authorization-server`.

For testing purposes, a script for creating JWT Bearer Tokens for client authentication is located at `scripts/create_test_token.rb`.

**NOTE**: Omejdn does not come with its own TLS server and needs to be run behind a reverse proxy in production setups.

## Configuration

### Signing keys

The server public/private key pair used to sign tokens is located at `keys/omejdn/omejdn.key`.
This file will be auto-generated, if it does not exist.
If you would like to use your own key, simply replace this file.
You may place other keys and certificates in this folder to have the keys be advertised via the JWKS endpoint (e.g. for key rollover).

### Clients

Clients are configured in `config/clients.yml`.
Have a look at the file to see the format.

Confidential clients need to authenticate using a JWT bearer.
This requires placing a non-expired certificate at `keys/clients/$(base64urlencode(CLIENT_ID)).cert`.
To have keys be automatically be copied to the correct position, you may specify `import_certfile` for that client in the client configuration file.
Only confidential clients may use the `client_credentials` grant.

In order to generate your own key pair with a self-signed pulic key
for testing, your can execute:

    $ openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem

### Users

Users are configured using one or more *User Databases*, or `user_db` plugins.
Which plugin you need to use depends on your setup, but here is a brief overview:

* `yaml` reads users from a YAML file (`config/users.yml` by default).
This plugin is useful for semi-static, small sets of users, such as Admin-accounts.
The configuration format is described in the docs.

* `sqlite` stores users and their attributes in a SQLite3 database. This is useful for larger local sets of users.

* `ldap` Connect to an existing LDAP directory. You will know when to use this.

### Scopes and Attributes

A client can request any subset of scopes in his `allowed scopes`,
configurable in the client configuration file.
If you define a set of attributes for a scope in `config/scope_mapping.yml`,
the `userinfo` endpoint response will also include this attribute.

(Note: You can also add those attributes to the Access- and ID Tokens.
Have a look at the `attributes` claim mapper plugin.)

Scopes are granted if the subject contains at least one such attribute.
Scopes of the form `k:v` are granted if the user contains an attribute with key `k` and value `v`.

In `config/scope_description.yml` you can configure a short description string
which is displayed to the user in an OpenID Connect flow upon requesting
authorization.

There are some special scopes you may want to use:

  - `openid`, `profile`, `email`: These scopes are defined by OpenID.
  - `omejdn:*`: These scopes are reserved for use with Omejdn and its APIs.
  Values include:
    - `omejdn:read` and `omejdn:write` for access to the User Selfservice API Plugin.
    - `omejdn:admin` for access to the Omejdn Admin API Plugin.

### Plugins

Omejdn's functionality can be customized through the use of plugins.
For more information please take a look at [the Plugin README](plugins/README.md).

## Using the Omejdn Docker Image

Omejdn comes with its own Docker images, which you can either grab from ghcr.io,
or build yourself like so:

```
$ docker build . -t my-omejdn-server
$ docker run -d  --name=omejdn -p 4567:4567 \
              -v $PWD/config:/opt/config \
              -v $PWD/keys:/opt/keys my-omejdn-server
```

Most of Omejdn's core features (excluding plugins) can be configured via environment variables, by upper-casing the config option and prepending `OMEJDN_`.
For instance, setting `OMEJDN_ISSUER` will overwrite the `issuer` configuration option.

To add an admin user, set `OMEJDN_ADMIN` to `username:password`.

## Supported Standards

This server mostly implements the following standards (potentially via plugins):

- Web Authorization Protocol (oauth)
  * [RFC 6749](https://datatracker.ietf.org/doc/rfc6749/) - The OAuth 2.0 Authorization Framework
  * [RFC 6750](https://datatracker.ietf.org/doc/rfc6750/) - The OAuth 2.0 Authorization Framework: Bearer Token Usage
  * [RFC 7519](https://datatracker.ietf.org/doc/rfc7519/) - JSON Web Token (JWT)
  * [RFC 7521](https://datatracker.ietf.org/doc/rfc7521/) - Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants
  * [RFC 7523](https://datatracker.ietf.org/doc/rfc7523/) - JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants
  * [RFC 7636](https://datatracker.ietf.org/doc/rfc7636/) - Proof Key for Code Exchange by OAuth Public Clients
  * [RFC 8414](https://datatracker.ietf.org/doc/rfc8414/) - OAuth 2.0 Authorization Server Metadata
  * [RFC 8707](https://datatracker.ietf.org/doc/rfc8707/) - Resource Indicators for OAuth 2.0
  * [RFC 9068](https://datatracker.ietf.org/doc/rfc9068/) - JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
  * [RFC 9101](https://datatracker.ietf.org/doc/rfc9101/) - The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)
  * [RFC 9126](https://datatracker.ietf.org/doc/rfc9126/) - OAuth 2.0 Pushed Authorization Requests
- OpenID Connect Protocol Suite
  * [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
  * [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
  * [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- Other Standards
  * [RFC 7033 - WebFinger](https://datatracker.ietf.org/doc/rfc7033/)
- Internet Drafts
  * [draft-spencer-oauth-claims-01](https://www.ietf.org/archive/id/draft-spencer-oauth-claims-01.txt)
  * [draft-ietf-oauth-security-topics-19](https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics/)
  * [draft-ietf-oauth-v2-1-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)


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

## Directory Structure

Omejdn uses the following directory structure:

```
\_ omejdn.rb                 (Omejdn Source code)
\_ lib/                      (Additional Source code)
\_ plugins/
    \_ api/                  (API Plugins)
    \_ claim_mapper/         (Claim Mapper Plugins)
    \_ user_db/              (User Database Plugins)
\_ config/
    \_ omejdn.yml            (The main configuration file)
    \_ clients.yml           (Client configuration file)
    \_ webfinger.yml         (Webfinger configuration)
    \_ oauth_providers.yml   (To configure external OpenID Providers)
    \_ scope_description.yml (Human-readable strings for Scopes)
    \_ scope_mapping.yml     (Mapping Scopes to Attributes)
\_ keys/
    \_ omejdn/               (Keys and Certificates to be JWKS-advertised)
        \_ omejdn.key        (The OAuth2 server private key)
    \_ clients/              (The public key certificates for clients)
\_ views/                    (Web-Pages)
\_ public/                   (Additional frontend resources (CSS+Images))
\_ tests/
    \_ test_*.rb             (Unit and E2E tests for Omejdn)
    \_ test_resources/       (Test vectors)
\_ scripts/                  (Convenience Scripts)
```
