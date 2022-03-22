# Access Scopes

The scopes granted to any successful client request are a subset of the requested scopes.
Omejdn does not provide a default set of scopes issued to any particular client.

The rules for determining whether to grant a scope
(not including gaining consent from an optional user) are as follows:

1. Any scope that is not included in the client's `scope` metadata is rejected.
1. The scope `openid` has a special purpose in OpenID and is granted
1. The "resource owner" (being a user in the case of the `authorization_code` grant and a client in the case of the `client_credentials` grant) is determined.
1. If a scope does not contain the character `:`, it is granted iff. the scope maps to (see below) at least one claim that is included as a key in the resource owner's attributes.
1. A scope is parsed as `k:v`, where `k` does not include the character `:`
1. A scope is granted iff. the resource owner contains an attribute with key `k` and value `v`.

### Examples

For a scope `omejdn:admin` to be granted in an `authorization_code` flow,
the requesting client must include `omejdn:admin` in its `scope` metadata,
and the user must have the following attribute:

```
- key: omejdn
  value: admin
```

For a scope `omejdn:admin` to be granted in an `client_credentials` flow,
the requesting client must include `omejdn:admin` in its `scope` metadata
and the same attribute as above.

For a scope `profile` to be granted in an `authorization_code` flow,
the requesting client must include `profile` in its `scope` metadata,
and the scope `profile` must map to at least one claim (say, `preferred_username`)
for which the user has an attribute like the following:

```
- key: preferred_username
  value: cooldude42
```

## Mapping Scopes to Claims

Scopes can be mapped to an array of claims in the YAML-formatted file `config/scope_mapping.yml`.

Mapping a claim there has (by default) two implications:

- They affect which scopes are potentially granted to a requesting client (see above)
- In OpenID authorization requests, they determine the claims included in the `userinfo` response.

## Providing a Description for Scopes

During the `authorization_code` flow, users are expected to grant or deny an authorization request.
As part of making an informed decision, the requested scopes are shown to them as is.
Depending on the naming scheme for the scopes, they might not be very intuitive however.

For this reason, it is recommended to provide a mapping from scopes to Strings of human-readable descriptions of the meaning of a scope in `config/scope_mapping.yml`.

## Reserved Scopes

Any scope having a prefix of `omejdn` is reserved for use within Omejdn or official plugins.
Improper usage of such scopes may result in unexpected errors after any update.