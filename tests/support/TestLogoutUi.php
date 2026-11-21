<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\Response\TextResponse;
use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Logout\LogoutUi;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TestLogoutUi implements LogoutUi
{
    /** @var array<string, string>|null the fields of the last confirmation screen */
    public ?array $confirmFields = null;

    public ?string $clientName = null;

    public ?string $endedSessionId = null;

    public function confirm(ServerRequestInterface $request, ?Client $client, array $fields): ResponseInterface
    {
        $this->confirmFields = $fields;
        $this->clientName = $client?->id();

        return new TextResponse('confirm logout', 200);
    }

    public function signedOut(ServerRequestInterface $request, ?string $redirectUri, ?string $endedSessionId): ResponseInterface
    {
        $this->endedSessionId = $endedSessionId;

        return $redirectUri === null ? new TextResponse('signed out', 200) : new RedirectResponse($redirectUri);
    }
}
