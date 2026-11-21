<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use Laminas\Diactoros\Response\TextResponse;
use PhpSso\OAuthServer\Authorization\AuthorizationUi;
use PhpSso\OAuthServer\Client\Client;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TestAuthorizationUi implements AuthorizationUi
{
    /** The request the last login screen was asked for, with the attributes the library added. */
    public ?ServerRequestInterface $loginRequest = null;

    public function loginRequired(ServerRequestInterface $request): ResponseInterface
    {
        $this->loginRequest = $request;

        return new TextResponse('login page', 200);
    }

    public function accessDenied(ServerRequestInterface $request, Client $client): ResponseInterface
    {
        return new TextResponse('no access to ' . $client->id(), 403);
    }
}
