<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Logout;

use PhpSso\OAuthServer\Grant\RefreshTokenStore;
use Psr\Clock\ClockInterface;

/**
 * What has to happen whenever a login session ends, for any reason (the person signed out, an administrator
 * ended it, a password was reset): refresh tokens and access tokens issued during it stop working, and
 * clients that support it are told.
 *
 * Call {@see self::sessionEnded()} from your own code after you ended the session. The end-session endpoint
 * calls it for you.
 */
final readonly class LogoutService
{
    public function __construct(
        private RefreshTokenStore $refreshTokens,
        private BackchannelLogout $backchannel,
        private ClockInterface $clock,
    ) {
    }

    /** @return list<LogoutDelivery> */
    public function sessionEnded(string $sessionId, string $userId): array
    {
        $this->refreshTokens->revokeSession($sessionId, $this->clock->now()->getTimestamp());

        return $this->backchannel->notify($sessionId, $userId);
    }
}
