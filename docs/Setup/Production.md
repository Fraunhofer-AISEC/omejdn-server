# Production-Ready setup

**IMPORTANT**: Keep in mind that Omejdn is a reasearch sandbox. There may be security relevant bugs and general inconsistencies. Use at your own risk.

Using Omejdn outside of testing environments requires essentially requires following
the steps described in the [Local Setup](./Local.md) or the [Docker Setup](./Docker.md)
and applying a few best practises described below:

## Using proper TLS

This is probably the most important Best Practise.

Many of the implemented standards strictly require the use of HTTPS.
Since Omejdn does not provide TLS by itself,
You need to use some sort of reverse Proxy and configure it appropriately.

You should pay special attention to the trust model your Server is operating in.
The use of self-signed certificates may be appropriate if every client knows about that certificate.

If Omejdn was configured with an `https://` issuer identifier,
all cookies issued by Omejdn have the `secure` flag enabled.
This means that you should signal to Omejdn what protocol was originally used via the `X-Forwarded-Proto` HTTP header.

See [here](../Integration/NginX.md) for an example setup using NginX.

## Redirecting Discovery Requests

Some setups require a few endpoints to be available at specific URLs.

In particular: If your issuer identifier contains a path component,
you should redirect as follows:

- `https://your.instance.org/.well-known/oauth-authorization-server/your/path`
should be redirected to Omejdn's `.well-known/oauth-authorization-server` endpoint
- `https://your.instance.org/.well-known/openid-configuration/your/path`
should be redirected to Omejdn's `.well-known/openid-configuration` endpoint

## Double checking Client Authentication

Public clients (e.g. those running in a browser) should use the `none` client authentication mechanism.
Confidential clients should preferrably use `private_key_jwt` or,
if this is unsupported, `client_secret_basic` or `client_secret_post`.