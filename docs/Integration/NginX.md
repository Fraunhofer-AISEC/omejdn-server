# Using NginX as a Reverse Proxy for Omejdn

It is strongly recommended to run Omejdn behind a reverse proxy such as NginX using TLS with appropriate encryption.

The following configurations describe an example server block for Omejdn for two different setups.
It is assumed that Omejdn is run locally on port 4567.
Please ensure that Omejdn is not accessible from the outside world (e.g. set `bind_to` to `127.0.0.1:4567` in the config file).
Please adapt these examples to your setup.

### Example Configuration: Pathless Issuer identifier (https://example.org/)

This is the easiest setup, but comes with a few drawbacks:

* Only one Server per Domain
* Hosting additional endpoints on this domain runs the risk of shadowing Omejdn's endpoints

```
server {
    listen      443 ssl;
    listen      [::]:443 ssl;
    server_name example.org;

    ssl_certificate     /path/to/your/certificate;
    ssl_certificate_key /path/to/your/key;
    
    location / {
        proxy_pass          http://localhost:4567;
        proxy_redirect      off;
        proxy_set_header    Host $host;
        proxy_set_header    X-Forwarded-Proto https;
    }
}
```

### Example Configuration: Issuer identifier with Path (https://example.org/my/path)

This configuration is more flexible, but does require a bit more setup.

```
server {
    listen      443 ssl;
    listen      [::]:443 ssl;
    server_name example.org;

    ssl_certificate     /path/to/your/certificate;
    ssl_certificate_key /path/to/your/key;
    
    location /my/path {
        proxy_pass          http://localhost:4567;
        proxy_redirect      off;
        proxy_set_header    Host $host;
        proxy_set_header    X-Forwarded-Proto https;
    }

    # RFC 8414 style .well-known URIs have to be handled separately
    # If you change this, it is recommended to at least redirect `/.well-known/oauth-authorization-server/my/path`,
    # And `/.well-known/openid-configuration/my/path` for backwards compatibility
    location /.well-known {
        rewrite /\.well-known/(.*)/my/path /my/path/.well-known/$1 last;
    }
}
```
