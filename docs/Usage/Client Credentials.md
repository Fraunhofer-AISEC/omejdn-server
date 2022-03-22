# Requesting Access through the Client Credentials Grant

To request certain scopes for a client acting on its own behalf,
send an HTTP POST request to Omejdn's token endpoint containing form encoded payload.

The required parameters are:

- `grant_type` with a value of `client_credentials`
- `scope` with a value of a space-concatenated list of requested scopes
- If no authentication mechanism is used, `client_id` with the `client_id` of the requesting client

Additionally, any confidential client must authenticate. See [Client Authentication](./Client Authentication.md) for more information.

### Example

*Note: examples contain additional line breaks and abbreviations and are not properly form encoded!*

Request using `private_key_jwt` client authentication:

```http request
POST /token HTTP/1.0
Content-Type: application/form-url-encoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=65fe[...]eab7
&scope=openid profile
```