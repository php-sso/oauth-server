<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use JsonException;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\Http\Responses;
use PhpSso\OAuthServer\Middleware\BearerTokenMiddleware;
use PhpSso\OAuthServer\Registration\ClientMetadataValidator;
use PhpSso\OAuthServer\Registration\ClientRegistration;
use PhpSso\OAuthServer\Registration\ClientRegistrations;
use PhpSso\OAuthServer\Token\TokenGenerator;
use PhpSso\OAuthServer\Token\TokenHash;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The dynamic client registration endpoint (RFC 7591). POST a JSON description of a client, get back its id,
 * its secret (confidential clients only) and a registration access token for managing it later
 * ({@see ClientConfigurationHandler}, RFC 7592).
 *
 * Mount it behind {@see \PhpSso\OAuthServer\AuthorizationServer::registrationMiddleware()}: only a caller holding an access
 * token with the registration scope may register. The client id of that token is kept as `registeredBy`.
 */
final readonly class ClientRegistrationHandler implements RequestHandlerInterface
{
    public function __construct(
        private ServerConfig $config,
        private Endpoints $endpoints,
        private ClientMetadataValidator $validator,
        private ClientRegistrations $registrations,
        private TokenGenerator $tokens,
        private ClockInterface $clock,
        private Responses $responses,
        private ErrorResponder $errors,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            if ($request->getMethod() !== 'POST') {
                throw OAuthException::invalidRequest('The registration endpoint only accepts POST.');
            }
            $registeredBy = $request->getAttribute(BearerTokenMiddleware::CLIENT_ID);
            if (!is_string($registeredBy)) {
                throw OAuthException::invalidToken('Registration needs an access token; mount this handler behind the registration middleware.');
            }

            $metadata = $this->validator->validate(self::jsonBody($request));
            $secret = $metadata->isConfidential() ? $this->tokens->generate() : null;
            $registrationToken = $this->tokens->generate();

            $registration = new ClientRegistration(
                $this->tokens->generate(),
                $metadata,
                $secret === null ? null : TokenHash::of($secret),
                TokenHash::of($registrationToken),
                $this->clock->now()->getTimestamp(),
                $registeredBy,
            );
            $this->registrations->save($registration);

            $body = self::describe($registration, Endpoints::url($this->config->issuer, $this->endpoints->registration)) + [
                'registration_access_token' => $registrationToken,
            ];
            if ($secret !== null) {
                $body['client_secret'] = $secret;
                $body['client_secret_expires_at'] = 0;
            }
        } catch (OAuthException $e) {
            return $this->errors->respond($e);
        }

        return $this->responses->noStore($this->responses->json($body, 201));
    }

    /**
     * The client information response (RFC 7591 section 3.2.1) without the secrets, which are not stored in the clear.
     *
     * @return array<string, mixed>
     */
    public static function describe(ClientRegistration $registration, string $registrationEndpoint): array
    {
        return [
            'client_id' => $registration->clientId,
            'client_id_issued_at' => $registration->issuedAt,
            'registration_client_uri' => rtrim($registrationEndpoint, '/') . '/' . rawurlencode($registration->clientId),
        ] + $registration->metadata->toArray();
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws OAuthException
     */
    public static function jsonBody(ServerRequestInterface $request): array
    {
        $parsed = $request->getParsedBody();
        if (is_array($parsed)) {
            return $parsed;
        }
        try {
            $data = json_decode((string) $request->getBody(), true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw OAuthException::invalidClientMetadata('The body must be a JSON object.');
        }
        if (!is_array($data) || ($data !== [] && array_is_list($data))) {
            throw OAuthException::invalidClientMetadata('The body must be a JSON object.');
        }

        return $data;
    }
}
