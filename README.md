# php-sso/oauth-server

An OAuth 2.0 and OpenID Connect authorization server for PSR-7 / PSR-15 applications.

- PSR-7 messages in and out, PSR-15 request handlers and middleware: it fits any framework.
- No third-party runtime dependencies: only the PSR interface packages and PHP's own `openssl` and `json`.
- Storage, people, clients and keys are interfaces you implement; nothing here knows about your database.
- Small on purpose, and strict by default.

## Install

```
composer require php-sso/oauth-server
```

PHP 8.2 or newer, with `ext-json` and `ext-openssl`.

## Documentation

The documentation is at **<https://php-sso.github.io/oauth-server/>**:

- [What it supports](https://php-sso.github.io/oauth-server/supported/): grants, OpenID Connect, logout, tokens, and what is not there yet.
- [Using it](https://php-sso.github.io/oauth-server/usage/): building the server, and what your application has to provide.
- [Roles, and APIs behind the server](https://php-sso.github.io/oauth-server/roles-and-apis/)
- [Verifying tokens this server did not sign](https://php-sso.github.io/oauth-server/verifying-tokens/)
- [Security behaviour](https://php-sso.github.io/oauth-server/security/) and the [threat model](https://php-sso.github.io/oauth-server/threat-model/)

The pages are in [`docs/content`](docs/content), built with Hugo and the
[php-sso docs theme](https://github.com/php-sso/docs-theme). Preview them with `hugo server --source docs`.

## Develop

```bash
composer install
composer check      # PHPStan (level max, strict rules, no baseline) and PHPUnit
```

Tests follow Arrange, Act, Assert, one file per method:
`tests/unit/PhpSso/OAuthServer/{Namespace}/{Class}/{Method}Test.php`.

## License

MIT. See [LICENSE](LICENSE).
