# Cryptographic Key Management

Omejdn naturally deals with several kinds of cryptographic keys.
The following provides an overview of how to handle them.

## Token Signing Keys

Omejdn's main signing key is located at `keys/omejdn/omejdn.key`.
If not provided, this file will be generated automatically when needed.

The signing key is used to sign any tokens Omejdn issues.
This includes access tokens as well as ID tokens.

All keys and X.509 certificates in `keys/omejdn/` are also advertised at Omejdn's `jwks_uri`.
For private keys (including the current signing key), only their public part is advertised.
This mechanism can be used for key rollover.
To roll over to a new key, rename `omejdn.key` and optionally provide a new signing key (if omitted, Omejdn will still generate a new one for you).

## Client Authentication Certificates

Confidential clients using the `private_key_jwt` authentication mechanism need to have an X.509 certificate installed at Omejdn.
This replaces the `jwks` client metadata.

Client certificates are stored in `keys/clients/`, and have a filename determined by Base64url-encoding the client's `client_id` and appending `.cert`.
For ease of configuration, clients may have an `import_certfile` claim pointing to a client certificate (with a path relative to Omejdn's root directory).
Upon seeing this claim, Omejdn will copy the client certificate to the correct location and afterwards delete the claim.

Client certificates may be issued by any CA or even self-signed.
The implicit trust model assumes that any Omejdn-registered certificate is to be considered valid.
The only enforced checks are that the certificate must be valid at the time of usage
(i.e. it must not have expired).

To generate your own self-signed certificates, you may execute

```
$ openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
```