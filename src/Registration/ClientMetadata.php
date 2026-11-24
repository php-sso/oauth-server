<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Registration;

use PhpSso\OAuthServer\Grant\GrantType;

/** The metadata of a registered client (RFC 7591 section 2), after validation. */
final readonly class ClientMetadata
{
    /**
     * @param list<string>    $redirectUris
     * @param list<string>    $responseTypes
     * @param list<GrantType> $grantTypes
     * @param list<string>    $scopes
     * @param list<string>    $contacts
     * @param list<string>    $postLogoutRedirectUris
     */
    public function __construct(
        public array $redirectUris,
        public array $responseTypes,
        public array $grantTypes,
        public string $tokenEndpointAuthMethod,
        public array $scopes,
        public ?string $clientName = null,
        public ?string $clientUri = null,
        public ?string $logoUri = null,
        public ?string $tosUri = null,
        public ?string $policyUri = null,
        public array $contacts = [],
        public ?string $softwareId = null,
        public ?string $softwareVersion = null,
        public ?string $backchannelLogoutUri = null,
        public array $postLogoutRedirectUris = [],
    ) {
    }

    public function isConfidential(): bool
    {
        return $this->tokenEndpointAuthMethod !== 'none';
    }

    /**
     * The metadata as the registration endpoints report it.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $fields = [
            'redirect_uris' => $this->redirectUris,
            'response_types' => $this->responseTypes,
            'grant_types' => array_map(static fn (GrantType $g): string => $g->value, $this->grantTypes),
            'token_endpoint_auth_method' => $this->tokenEndpointAuthMethod,
            'scope' => implode(' ', $this->scopes),
            'client_name' => $this->clientName,
            'client_uri' => $this->clientUri,
            'logo_uri' => $this->logoUri,
            'tos_uri' => $this->tosUri,
            'policy_uri' => $this->policyUri,
            'contacts' => $this->contacts,
            'software_id' => $this->softwareId,
            'software_version' => $this->softwareVersion,
            'backchannel_logout_uri' => $this->backchannelLogoutUri,
            'post_logout_redirect_uris' => $this->postLogoutRedirectUris,
        ];

        return array_filter($fields, static fn (mixed $v): bool => $v !== null && $v !== []);
    }
}
