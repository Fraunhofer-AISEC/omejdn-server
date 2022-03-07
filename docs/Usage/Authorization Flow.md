# Requesting Access through the Authorization Code Grant

To request access to certain resources on behalf of a user,
redirect them to Omejdn's authorization endpoint
and add the necessary request parameters, which are:

- `response_type` must have a value of `code`
- `scope` must list all requested scopes. OpenID requests must include `openid`.
- `client_id` is the requesting client's `client_id`
- `state` may be any string that will be returned to the client unaltered
- `redirect_uri` must be a redirection URI registered in the client's metadata.

In the future, the usage of `PKCE` may be mandatory as well.

The user will be asked to log in and grant the request before being redirected to the client.

The resulting `code` may be used at the authorization endpoint.

### Example

*Note: all examples have additional line breaks and do not use the proper encoding.*

Request:

```
https://example.org/authorize?
response_type=code
&scope=openid profile
&client_id=my_client
&state=jhsfdgvksb
&redirect_uri=https://localhost
```

Response:

```
https://localhost?
iss=https://example.org/
&state=jhsfdgvksb
&code=sadjvhbkajvhbakjvfbdjvbjdhfvb
```

## Pushed Authorization Requests

When the request parameters exceed a certain length,
it may be desirable to transmit them to Omejdn out of bounds.
This may be done via Pushed Authorization Request (PAR).

Essentially, it works like this:

- The client sends the request parameters as an HTTP POST request to Omejdn's PAR endpoint.
The client must authenticate as described in [Client Authentication](<./Client Authentication.md>).
- Omejdn responds with a `request_uri`
- Instead of most other parameters, this `request_uri` is included in the authorization request parameters.