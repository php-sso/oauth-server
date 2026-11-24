---
title: Client registration
weight: 5
lead: Let applications register themselves (RFC 7591) and manage that registration (RFC 7592).
---

Normally you create each client by hand. With dynamic client registration an application sends a JSON description of
itself to the registration endpoint and gets a client id back. This is what MCP clients and other tools you do not know
in advance need.

An open door would let anyone create clients on your login server, so registration is locked: the caller must hold an
access token with the `client:register` scope. Give that scope only to the clients you trust to register others (for
example your own backend, which registers a client for each connection a user creates).

## Turn it on

```php
$registrations = new MyClientRegistrations();   // implements ClientRegistrations, on your database

$server = new AuthorizationServer(
    /* ...as before, but pass ClientsWithRegistrations as the ClientRepository... */
    new ClientsWithRegistrations($myClients, $registrations),
    /* ... */
    registrations: $registrations,
    registration: new RegistrationConfig(),   // optional
);

$router->post('/register', $server->registrationHandler(), $server->registrationMiddleware());
$router->map(['GET', 'PUT', 'DELETE'], '/register/{client_id}', $server->clientConfigurationHandler());
```

Add `client:register` to `ServerConfig::$scopes` and allow it on the client that registers others. Registered clients can
never hold it. The discovery document gets a `registration_endpoint` when registration is on.

## The flow

1. Your backend gets a token: `client_credentials` with `scope=client:register`.
2. It POSTs the metadata to `/register` with `Authorization: Bearer <token>`:

   ```json
   {"redirect_uris": ["http://127.0.0.1:8123/callback"], "token_endpoint_auth_method": "none", "client_name": "My MCP client"}
   ```
3. The response (201) holds `client_id`, `registration_access_token`, `registration_client_uri` and, for confidential
   clients, `client_secret`. **Secrets are shown once**: only their hashes are stored.
4. The client (or your backend for it) manages the registration at `registration_client_uri` with the registration access
   token: `GET` reads, `PUT` replaces (send the whole description plus `client_id`), `DELETE` removes (204).

The two tokens are different: the `client:register` token may create clients; a registration access token may manage
exactly one.

## What is accepted

`RegistrationConfig` sets the limits. By default a client may use `authorization_code` and `refresh_token`, any of the
authentication methods `none`, `client_secret_basic` and `client_secret_post`, and any scope the server offers except the
registration scope (`openid` when it names none). `client_credentials` is off, so a self-registered client never gets a
machine identity.

Redirect URIs must be absolute, free of fragments and credentials, and `https`; `http` only for `localhost`, `127.0.0.1`
and `[::1]`. Private-use schemes such as `com.example.app:/cb` are allowed for native apps (switch off with
`allowCustomSchemeRedirects`); `javascript:`, `data:`, `file:` and similar never are. Informational URLs (`client_uri`,
`logo_uri`, `tos_uri`, `policy_uri`) must be https. `backchannel_logout_uri` must be https and name a host, not an IP address.
Errors use the RFC codes `invalid_redirect_uri` and `invalid_client_metadata`. Unknown fields are ignored; software
statements are refused (`invalid_software_statement`).

## Notes

- `client_name`, `logo_uri` and the other fields are chosen by the registering party. Escape them wherever you show them,
  such as a consent page.
- Deleting a client stops codes and refresh tokens (the client lookup fails). Access tokens already issued live until they expire.
- Because secrets are hashed, a `GET` does not repeat the `client_secret` or the registration access token, which RFC 7592
  allows servers to do only when they keep them. A `PUT` that makes a public client confidential issues a new secret.
- `registeredBy` on each registration is the client id of the token that created it, so you can list or clean up
  what one registrar made.
- Rate limit the registration endpoint like the token endpoint.
