# Using the Omejdn Docker Image

Omejdn comes with its own Docker images, which you can either grab from ghcr.io, or build yourself like so:

```
$ docker build . -t my-omejdn-server
$ docker run -d  --name=omejdn -p 4567:4567 \
              -v $PWD/config:/opt/config \
              -v $PWD/keys:/opt/keys my-omejdn-server
```

Most of Omejdn's core features (excluding plugins) can be configured via environment variables, by upper-casing the config option and prepending `OMEJDN_`. For instance, setting `OMEJDN_ISSUER` will overwrite the `issuer` configuration option.

To add an admin user, set `OMEJDN_ADMIN` to `username:password`.