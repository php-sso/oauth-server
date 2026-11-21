<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Logout;

use PhpSso\OAuthServer\Client\Client;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/** The screens of the end-session endpoint, and the one place the browser's own session cookie is dealt with. */
interface LogoutUi
{
    /**
     * Asks the person whether they want to sign out. Called when the request came without a valid
     * `id_token_hint`, so a stray link cannot sign anybody out.
     *
     * The form must POST to the end-session endpoint with every entry of `$fields` as a hidden input plus
     * `confirmed=1`. Protect it with your own CSRF check before the request reaches the handler.
     *
     * @param array<string, string> $fields
     */
    public function confirm(ServerRequestInterface $request, ?Client $client, array $fields): ResponseInterface;

    /**
     * The request is dealt with. Answer: redirect to `$redirectUri` when it is not null, otherwise show a
     * "you are signed out" page.
     *
     * `$endedSessionId` is the login session that was ended, or null if there was none. Clear the browser's
     * session cookie here when it belongs to that session; if the browser is signed in under another session
     * (the client named a different one), leave it alone.
     */
    public function signedOut(ServerRequestInterface $request, ?string $redirectUri, ?string $endedSessionId): ResponseInterface;
}
