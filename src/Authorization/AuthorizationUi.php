<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Authorization;

use PhpSso\OAuthServer\Client\Client;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/** The two screens the authorization endpoint cannot draw itself. The application owns them. */
interface AuthorizationUi
{
    /**
     * Nobody is signed in: send the browser to your login page, and bring it back to this request
     * afterwards. Not called for `prompt=none`, which answers `login_required` to the client instead.
     */
    public function loginRequired(ServerRequestInterface $request): ResponseInterface;

    /** The person is signed in but the {@see AccessPolicy} says they may not use this client. */
    public function accessDenied(ServerRequestInterface $request, Client $client): ResponseInterface;
}
