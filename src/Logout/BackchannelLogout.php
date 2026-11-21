<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Logout;

use PhpSso\OAuthServer\Client\ClientRepository;
use PhpSso\OAuthServer\Client\SupportsLogout;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Jwt\JwtEncoder;
use PhpSso\OAuthServer\Token\TokenGenerator;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use stdClass;

/**
 * OpenID Connect Back-Channel Logout 1.0: tells every client that took part in a session, and registered a
 * logout URI, that the session ended, by POSTing a signed logout token to it.
 *
 * Delivery is one attempt per client and never throws: a client that is down must not stop anybody from
 * signing out. The outcomes are returned so the application can log or retry them.
 *
 * The PSR-18 client you pass decides timeouts and which addresses may be reached. Set a short timeout, and
 * if clients can register their own URIs, keep it from reaching your internal network.
 */
final readonly class BackchannelLogout
{
    private const EVENT = 'http://schemas.openid.net/event/backchannel-logout';
    private const TOKEN_TTL = 120;

    public function __construct(
        private ServerConfig $config,
        private ClientRepository $clients,
        private SessionRegistry $sessions,
        private JwtEncoder $encoder,
        private TokenGenerator $generator,
        private ClockInterface $clock,
        private ClientInterface $http,
        private RequestFactoryInterface $requests,
        private StreamFactoryInterface $streams,
    ) {
    }

    /** @return list<LogoutDelivery> one entry per client that was supposed to be told */
    public function notify(string $sessionId, string $userId): array
    {
        $deliveries = [];
        foreach ($this->sessions->clientsOf($sessionId) as $clientId) {
            $client = $this->clients->find($clientId);
            $uri = $client instanceof SupportsLogout ? $client->backchannelLogoutUri() : null;
            if ($client === null || $uri === null) {
                continue;
            }
            $deliveries[] = $this->deliver($clientId, $uri, $this->logoutToken($clientId, $userId, $sessionId));
        }

        return $deliveries;
    }

    /** @return non-empty-string */
    private function logoutToken(string $clientId, string $userId, string $sessionId): string
    {
        $now = $this->clock->now()->getTimestamp();

        // No `nonce`: the spec forbids one, so a logout token cannot be mistaken for an ID token.
        return $this->encoder->encode([
            'iss' => $this->config->issuer,
            'sub' => $userId,
            'aud' => $clientId,
            'iat' => $now,
            'exp' => $now + self::TOKEN_TTL,
            'jti' => $this->generator->generate(),
            'sid' => $sessionId,
            'events' => [self::EVENT => new stdClass()],
        ], 'logout+jwt');
    }

    private function deliver(string $clientId, string $uri, string $token): LogoutDelivery
    {
        if (!str_starts_with($uri, 'https://') && !str_starts_with($uri, 'http://')) {
            return new LogoutDelivery($clientId, $uri, false, null, 'The logout URI is not an http(s) URL.');
        }

        $request = $this->requests->createRequest('POST', $uri)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Cache-Control', 'no-store')
            ->withBody($this->streams->createStream(http_build_query(['logout_token' => $token], '', '&', PHP_QUERY_RFC3986)));

        try {
            $status = $this->http->sendRequest($request)->getStatusCode();
        } catch (ClientExceptionInterface $e) {
            return new LogoutDelivery($clientId, $uri, false, null, $e->getMessage());
        }

        return new LogoutDelivery($clientId, $uri, $status >= 200 && $status < 300, $status, $status >= 200 && $status < 300 ? null : "The client answered with HTTP {$status}.");
    }
}
