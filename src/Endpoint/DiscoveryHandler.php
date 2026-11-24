<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Http\Responses;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The discovery document: OpenID Connect Discovery (`/.well-known/openid-configuration`) and RFC 8414
 * (`/.well-known/oauth-authorization-server`) use the same metadata, so mount this handler on both.
 */
final readonly class DiscoveryHandler implements RequestHandlerInterface
{
    /** @param list<string> $claims The claim names your UserClaimsProvider can release. */
    public function __construct(
        private ServerConfig $config,
        private Endpoints $endpoints,
        private Responses $responses,
        private array $claims,
        private bool $registrationEnabled = false,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $issuer = $this->config->issuer;
        $url = static fn (string $path): string => Endpoints::url($issuer, $path);

        $metadata = [
            'issuer' => $issuer,
            'authorization_endpoint' => $url($this->endpoints->authorization),
            'token_endpoint' => $url($this->endpoints->token),
            'userinfo_endpoint' => $url($this->endpoints->userinfo),
            'jwks_uri' => $url($this->endpoints->jwks),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => array_map(static fn (GrantType $g): string => $g->value, GrantType::cases()),
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => $this->config->scopes,
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'code_challenge_methods_supported' => ['S256'],
            'claims_supported' => $this->claims,
            'authorization_response_iss_parameter_supported' => true,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'end_session_endpoint' => $url($this->endpoints->endSession),
            'device_authorization_endpoint' => $url($this->endpoints->deviceAuthorization),
            'revocation_endpoint' => $url($this->endpoints->revocation),
            'revocation_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'introspection_endpoint' => $url($this->endpoints->introspection),
            'introspection_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
            'frontchannel_logout_supported' => false,
        ];

        if ($this->registrationEnabled) {
            $metadata['registration_endpoint'] = $url($this->endpoints->registration);
        }

        return $this->responses->json($metadata, 200, ['Cache-Control' => 'public, max-age=300']);
    }
}
