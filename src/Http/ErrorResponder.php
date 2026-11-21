<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Http;

use PhpSso\OAuthServer\Exception\OAuthException;
use Psr\Http\Message\ResponseInterface;

/**
 * Turns an error that cannot be sent back to the client application into a response. That is every
 * error at the token and userinfo endpoints, and the authorization errors that happen before the
 * redirect URI is known to be safe. The default answers with JSON; an application can show a page.
 */
interface ErrorResponder
{
    public function respond(OAuthException $error): ResponseInterface;
}
