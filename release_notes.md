# Release Notes

Please read these notes carefully before updating.
**Bold** notes require manual intervention.

## V 1.2.0

- Added support for dynamically chosen claim values
- Added several configuration options to `omejdn.yml`, which were previously only configurable via environment variables.
- Bugfixes and tests

## V 1.1.1

- **The default user backend for new users can (and must) now be specified using the new `user_backend_default` key in `omejdn.yml`**
- Mainly Bugfixes

## V 1.1.0

- **Client certificate files are now chosen automatically. You may import your current certs by specifying a file as `import_certfile` for each client. `certfile` is now depricated**
- **The user selfservice API must now be explicitly enabled in `omejdn.yml`**
- RFC 8707 resource indication capabilities