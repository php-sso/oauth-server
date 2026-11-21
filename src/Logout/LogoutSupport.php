<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Logout;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * What the application provides so that signing out works everywhere: which clients took part in which session,
 * how to end a session, the screens of the end-session endpoint, and a way to reach the clients' logout URIs.
 */
final readonly class LogoutSupport
{
    public function __construct(
        public SessionRegistry $sessions,
        public SessionTerminator $terminator,
        public LogoutUi $ui,
        public ClientInterface $httpClient,
        public RequestFactoryInterface $requestFactory,
    ) {
    }
}
