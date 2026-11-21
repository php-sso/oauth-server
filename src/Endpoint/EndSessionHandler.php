<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use PhpSso\OAuthServer\Client\ClientRepository;
use PhpSso\OAuthServer\Client\SupportsLogout;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\Http\Params;
use PhpSso\OAuthServer\Jwt\InvalidJwt;
use PhpSso\OAuthServer\Jwt\JwtDecoder;
use PhpSso\OAuthServer\Logout\LogoutService;
use PhpSso\OAuthServer\Logout\LogoutUi;
use PhpSso\OAuthServer\Logout\SessionTerminator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The end-session endpoint (OpenID Connect RP-Initiated Logout 1.0).
 *
 * A client sends the browser here with `id_token_hint` (the ID token it received), and optionally
 * `post_logout_redirect_uri`, `state` and `client_id`. With a valid hint the session ends right away.
 * Without one, the person is asked to confirm first, so a stray link cannot sign them out.
 *
 * Ending a session means: your {@see SessionTerminator} marks it ended, the tokens issued during it are revoked,
 * and clients that registered a back-channel logout URI are told ({@see LogoutService}).
 *
 * Who is signed in comes from the request attributes {@see AuthorizationHandler::USER_ID} and
 * {@see AuthorizationHandler::SESSION_ID}, as for the authorization endpoint.
 */
final readonly class EndSessionHandler implements RequestHandlerInterface
{
    public function __construct(
        private ServerConfig $config,
        private ClientRepository $clients,
        private JwtDecoder $decoder,
        private SessionTerminator $terminator,
        private LogoutService $logout,
        private LogoutUi $ui,
        private ErrorResponder $errors,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $isPost = $request->getMethod() === 'POST';

        try {
            $params = $isPost ? Params::fromBody($request) : Params::fromQuery($request);
            $hint = $params->string('id_token_hint');
            $token = $hint === null ? null : $this->verifiedHint($hint);

            $clientId = $params->string('client_id');
            if ($token !== null) {
                if ($clientId !== null && $clientId !== $token['audience']) {
                    throw OAuthException::invalidRequest('The client_id does not match the id_token_hint.');
                }
                $clientId = $token['audience'];
            }
            $client = $clientId === null ? null : $this->clients->find($clientId);

            $redirect = null;
            $redirectUri = $params->string('post_logout_redirect_uri');
            if ($redirectUri !== null) {
                if (!$client instanceof SupportsLogout || !in_array($redirectUri, $client->postLogoutRedirectUris(), true)) {
                    throw OAuthException::invalidRequest('The post_logout_redirect_uri is not registered for this client.');
                }
                $state = $params->string('state');
                $redirect = $redirectUri . ($state === null ? '' : (str_contains($redirectUri, '?') ? '&' : '?') . http_build_query(['state' => $state], '', '&', PHP_QUERY_RFC3986));
            }
            $confirmed = $token !== null || ($isPost && $params->string('confirmed') === '1');
            $fields = array_filter([
                'client_id' => $clientId,
                'post_logout_redirect_uri' => $redirectUri,
                'state' => $params->string('state'),
            ], static fn (?string $v): bool => $v !== null);
        } catch (OAuthException $e) {
            return $this->errors->respond($e);
        }

        $currentUser = $request->getAttribute(AuthorizationHandler::USER_ID);
        $currentSession = $request->getAttribute(AuthorizationHandler::SESSION_ID);
        $currentUser = is_string($currentUser) && $currentUser !== '' ? $currentUser : null;
        $currentSession = is_string($currentSession) && $currentSession !== '' ? $currentSession : null;

        if (!$confirmed && $currentSession !== null) {
            return $this->ui->confirm($request, $client, $fields);
        }

        // Which session ends: the one the ID token names, or else the browser's own, but only for the same person.
        $sessionId = null;
        $subject = null;
        if ($token !== null) {
            $subject = $token['subject'];
            $sessionId = $token['session'] ?? ($token['subject'] === $currentUser ? $currentSession : null);
        } elseif ($confirmed) {
            $subject = $currentUser;
            $sessionId = $currentSession;
        }

        if ($sessionId !== null && $subject !== null) {
            $this->terminator->terminate($sessionId);
            $this->logout->sessionEnded($sessionId, $subject);
        } else {
            $sessionId = null;
        }

        return $this->ui->signedOut($request, $redirect, $sessionId);
    }

    /**
     * An ID token this server issued. Expiry is ignored on purpose: the token a client holds is usually old
     * by the time it asks to log out. Access tokens are refused.
     *
     * @return array{audience: string, subject: string, session: string|null}
     *
     * @throws OAuthException
     */
    private function verifiedHint(string $jwt): array
    {
        $invalid = OAuthException::invalidRequest('The id_token_hint is not a valid ID token from this server.');

        try {
            $decoded = $this->decoder->decode($jwt);
        } catch (InvalidJwt) {
            throw $invalid;
        }
        $claims = $decoded['claims'];
        $audience = $claims['aud'] ?? null;
        $audience = is_array($audience) ? ($audience[0] ?? null) : $audience;
        $subject = $claims['sub'] ?? null;
        $session = $claims['sid'] ?? null;

        if (($claims['iss'] ?? null) !== $this->config->issuer
            || ($decoded['header']['typ'] ?? null) !== 'JWT' // an ID token only: not an access token, not a logout token
            || !is_string($audience) || $audience === '' || !is_string($subject) || $subject === ''
        ) {
            throw $invalid;
        }

        return ['audience' => $audience, 'subject' => $subject, 'session' => is_string($session) && $session !== '' ? $session : null];
    }
}
