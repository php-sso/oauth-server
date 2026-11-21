<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Client;

use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\Params;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Identifies the client calling the token endpoint (RFC 6749 section 2.3): HTTP Basic or credentials in
 * the form body for confidential clients, just the client id for public ones. Every failure looks the
 * same, so the response does not reveal which client ids exist.
 */
final readonly class ClientAuthenticator
{
    public function __construct(private ClientRepository $clients)
    {
    }

    /** @throws OAuthException */
    public function authenticate(ServerRequestInterface $request, Params $body): Client
    {
        $header = $request->getHeaderLine('Authorization');
        $bodyId = $body->string('client_id');
        $bodySecret = $body->string('client_secret');

        if (preg_match('/^Basic\s+(\S+)$/i', $header, $match) === 1) {
            if ($bodySecret !== null) {
                throw OAuthException::invalidRequest('Authenticate the client in one way only: the Authorization header or the form body.');
            }
            [$id, $secret] = $this->basicCredentials($match[1]);
            if ($bodyId !== null && $bodyId !== $id) {
                throw OAuthException::invalidRequest('The client_id does not match the Authorization header.');
            }
        } else {
            $id = $bodyId;
            $secret = $bodySecret;
        }

        $failure = OAuthException::invalidClient('Client authentication failed.');
        if ($id === null) {
            throw $failure;
        }
        $client = $this->clients->find($id);
        if ($client === null) {
            if ($secret !== null && $this->clients instanceof EqualisesVerificationTime) {
                $this->clients->spendVerificationTime($secret); // an unknown id must not answer faster than a wrong secret
            }
            throw $failure;
        }

        if ($client->isConfidential()) {
            if ($secret === null || !$this->clients->verifySecret($client, $secret)) {
                throw $failure;
            }
        } elseif ($secret !== null) {
            throw $failure; // a public client has no secret; one that sends it is not what we registered
        }

        return $client;
    }

    /** @return array{string, string} */
    private function basicCredentials(string $encoded): array
    {
        $decoded = base64_decode($encoded, true);
        $separator = $decoded === false ? false : strpos($decoded, ':');
        if ($decoded === false || $separator === false) {
            throw OAuthException::invalidClient('Client authentication failed.');
        }

        // RFC 6749 section 2.3.1: both parts are form-urlencoded before being joined.
        return [urldecode(substr($decoded, 0, $separator)), urldecode(substr($decoded, $separator + 1))];
    }
}
