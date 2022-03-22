# Client Authentication

Every request involving direct communication from a client to Omejdn is required to contain some form of authorization from the client.
The client authentication method is configured in the [Client Configuration File](../Configuration/Clients.md).

**RECOMMENDATION:**
For individual clients running in a protected environment capable of storing secrets,
one should aim to use the `private_key_jwt` method.
Only if the client is incapable of using this method may the `client_secret_*` methods be acceptable.
Clients not running in such an environment should be considered public
and any secrets published along with them (even in non-disclosed source code) compromised.
The recommended method for such clients is therefore `none`.

The following describes authentication using each of the supported methods.

## none

Clients using this authentication method are referred to as "public clients".
They are not by any means "authenticated" and mere knowledge of a `client_id` must not be considered as a means of authentication.
This is the recommended method for clients running on an end-user's device.

While no authentication method is to be applied, public clients need to include their `client_id` in most requests for identification.

## client_secret_basic

Clients using this authentication method need to prove their knowledge of a metadata claim called `client_secret` by providing it together with their `client_id` in an HTTP Authorization Header:

```http request
POST /token HTTP/1.0
Content-Type: application/form-url-encoded
Authorization: <Header>

grant_type=client_credentials
&scope=openid profile
```

Here, `<Header>` denotes the Base64 encoding of `<client_id>:<client_secret>`.

## client_secret_post

Clients using this authentication method need to prove their knowledge of a metadata claim called `client_secret` by providing it together with their `client_id` in the request parameters:

An example request looks as follows:

```http request
POST /token HTTP/1.0
Content-Type: application/form-url-encoded

grant_type=client_credentials
&client_id=<client_id>
&client_secret=<client_secret>
&scope=openid profile
```

## private_key_jwt

Clients using this authentication method need to prove their knowledge of a secret key whose public counterpart is registered at the authorization server.
See [Keys](../Configuration/Keys.md) for the relevant configuration.

An example request looks as follows:

```http request
POST /token HTTP/1.0
Content-Type: application/form-url-encoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=65fe[...]eab7
&scope=openid profile
```

Here, the `client_assertion` is a signed JWT using the private key of the client
containing the following claims:

```json
{
  "iss": <client_id>,
  "sub": <client_id>,
  "exp": <current UNIX time> + 3600,
  "nbf": <current UNIX time>,
  "iat": <current UNIX time>,
  "aud": <An identifier accepted by Omejdn>
}
```

Values accepted as `aud` can be configured as described in [Main Configuration](../Configuration/Main Configuration.md).

For your convenience, a script creating such JWT bearers is provided in `scripts/create_test_token.rb`.