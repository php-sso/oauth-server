<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\Http\Responses;
use PhpSso\OAuthServer\Registration\ClientMetadataValidator;
use PhpSso\OAuthServer\Registration\ClientRegistration;
use PhpSso\OAuthServer\Registration\ClientRegistrations;
use PhpSso\OAuthServer\Registration\RegistrarPolicy;
use PhpSso\OAuthServer\Token\TokenGenerator;
use PhpSso\OAuthServer\Token\TokenHash;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The client configuration endpoint (RFC 7592): a registered client reads (GET), replaces (PUT) or deletes (DELETE)
 * its own registration, using the registration access token it got when it registered.
 *
 * Mount it on `{registration endpoint}/{client_id}`. The client id comes from the request attribute {@see self::CLIENT_ID}
 * when your router sets it, and from the last path segment otherwise.
 *
 * Differences from the RFC, because secrets are only stored as hashes: a read does not repeat the client secret or the
 * registration access token. An update that changes a client from public to confidential issues a new secret.
 */
final readonly class ClientConfigurationHandler implements RequestHandlerInterface
{
    public const CLIENT_ID = 'oauth.registration.client_id';

    public function __construct(
        private ServerConfig $config,
        private Endpoints $endpoints,
        private ClientMetadataValidator $validator,
        private ClientRegistrations $registrations,
        private TokenGenerator $tokens,
        private Responses $responses,
        private ErrorResponder $errors,
        private ?RegistrarPolicy $policy = null,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $registration = $this->authenticate($request);
            $endpoint = Endpoints::url($this->config->issuer, $this->endpoints->registration);

            switch ($request->getMethod()) {
                case 'GET':
                    $body = ClientRegistrationHandler::describe($registration, $endpoint);
                    break;
                case 'PUT':
                    $body = $this->update($registration, $request, $endpoint);
                    break;
                case 'DELETE':
                    $this->registrations->delete($registration->clientId);

                    return $this->responses->noStore($this->responses->empty(204));
                default:
                    throw OAuthException::invalidRequest('The client configuration endpoint accepts GET, PUT and DELETE.');
            }
        } catch (OAuthException $e) {
            return $this->errors->respond($e);
        }

        return $this->responses->noStore($this->responses->json($body));
    }

    /**
     * @return array<string, mixed>
     *
     * @throws OAuthException
     */
    private function update(ClientRegistration $registration, ServerRequestInterface $request, string $endpoint): array
    {
        $input = ClientRegistrationHandler::jsonBody($request);
        if (($input['client_id'] ?? null) !== $registration->clientId) {
            throw OAuthException::invalidRequest('The body must contain the client_id of this client.');
        }
        if (isset($input['client_secret']) && (!is_string($input['client_secret']) || !$registration->verifySecret($input['client_secret']))) {
            throw OAuthException::invalidRequest('The client_secret does not match; a secret cannot be chosen by the client.');
        }

        $registrar = $registration->registeredBy;
        $metadata = $this->validator->validate($input, $registrar === null ? null : $this->policy?->allowedScopes($registrar));
        $secret = null;
        $secretHash = $registration->secretHash;
        if (!$metadata->isConfidential()) {
            $secretHash = null;
        } elseif ($secretHash === null) {
            $secret = $this->tokens->generate();
            $secretHash = TokenHash::of($secret);
        }

        $updated = $registration->withMetadata($metadata, $secretHash);
        $this->registrations->save($updated);

        $body = ClientRegistrationHandler::describe($updated, $endpoint);
        if ($secret !== null) {
            $body['client_secret'] = $secret;
            $body['client_secret_expires_at'] = 0;
        }

        return $body;
    }

    /**
     * Every failure is the same 401, so the answer does not reveal which client ids exist.
     *
     * @throws OAuthException
     */
    private function authenticate(ServerRequestInterface $request): ClientRegistration
    {
        $id = $request->getAttribute(self::CLIENT_ID);
        if (!is_string($id)) {
            $segments = explode('/', rtrim($request->getUri()->getPath(), '/'));
            $id = rawurldecode(end($segments));
        }

        $registration = $this->registrations->find($id);
        $given = preg_match('/^Bearer\s+([A-Za-z0-9._~+\/-]+=*)$/', $request->getHeaderLine('Authorization'), $match) === 1 ? $match[1] : '';
        $known = $registration === null ? TokenHash::of('unknown client') : $registration->registrationTokenHash;
        $matches = hash_equals($known, TokenHash::of($given));

        if ($registration === null || !$matches) {
            throw OAuthException::invalidToken('Send the registration access token as "Authorization: Bearer <token>".');
        }

        return $registration;
    }
}
