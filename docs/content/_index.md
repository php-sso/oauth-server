---
title: oauth-server
lead: An OAuth 2.0 and OpenID Connect authorization server for PSR-7 / PSR-15 applications.
actions:
  - name: Install it
    url: /installation/
  - name: What it supports
    url: /supported/
---

- PSR-7 messages in and out, PSR-15 request handlers and middleware: it fits any framework.
- No third-party runtime dependencies: only the PSR interface packages and PHP's own `openssl` and `json`.
- Storage, people, clients and keys are interfaces you implement; nothing here knows about your database.
- Small on purpose, and strict by default.
