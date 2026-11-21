<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Logout;

/** The outcome of telling one client that a session ended. */
final readonly class LogoutDelivery
{
    public function __construct(
        public string $clientId,
        public string $uri,
        public bool $delivered,
        /** The HTTP status the client answered with, or null when the request could not be sent. */
        public ?int $status,
        public ?string $error,
    ) {
    }
}
