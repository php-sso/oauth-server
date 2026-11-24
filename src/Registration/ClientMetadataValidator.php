<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Registration;

use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\GrantType;

/** Turns the JSON of a registration request into {@see ClientMetadata}, or says what is wrong with it. Unknown fields are ignored (RFC 7591 section 2). */
final readonly class ClientMetadataValidator
{
    private const DANGEROUS_SCHEMES = ['javascript', 'data', 'file', 'vbscript', 'about', 'blob', 'ftp'];

    /** @var list<string> */
    private array $allowedScopes;

    public function __construct(private ServerConfig $server, private RegistrationConfig $config)
    {
        $allowed = $config->allowedScopes ?? $server->scopes;
        $this->allowedScopes = array_values(array_filter($allowed, static fn (string $s): bool => $s !== $config->scope));
    }

    /**
     * @param array<array-key, mixed> $input
     *
     * @throws OAuthException
     */
    public function validate(array $input): ClientMetadata
    {
        if (array_key_exists('software_statement', $input)) {
            throw OAuthException::invalidSoftwareStatement('Software statements are not supported.');
        }

        $method = $this->string($input, 'token_endpoint_auth_method') ?? 'client_secret_basic';
        if (!in_array($method, $this->config->allowedAuthMethods, true)) {
            throw OAuthException::invalidClientMetadata("The token_endpoint_auth_method {$method} is not supported.");
        }

        $grants = $this->grants($input);
        $responseTypes = $this->stringList($input, 'response_types') ?? (in_array(GrantType::AuthorizationCode, $grants, true) ? ['code'] : []);
        foreach ($responseTypes as $type) {
            if ($type !== 'code') {
                throw OAuthException::invalidClientMetadata("The response type {$type} is not supported.");
            }
        }
        $usesCode = in_array(GrantType::AuthorizationCode, $grants, true);
        if ($usesCode !== in_array('code', $responseTypes, true)) {
            throw OAuthException::invalidClientMetadata('The grant type authorization_code and the response type code go together.');
        }
        if ($method === 'none' && in_array(GrantType::ClientCredentials, $grants, true)) {
            throw OAuthException::invalidClientMetadata('The client_credentials grant needs a client that authenticates with a secret.');
        }

        $redirects = $this->redirectUris($input, $usesCode);

        return new ClientMetadata(
            redirectUris: $redirects,
            responseTypes: $responseTypes,
            grantTypes: $grants,
            tokenEndpointAuthMethod: $method,
            scopes: $this->scopes($input),
            clientName: $this->text($input, 'client_name', 100),
            clientUri: $this->url($input, 'client_uri'),
            logoUri: $this->url($input, 'logo_uri'),
            tosUri: $this->url($input, 'tos_uri'),
            policyUri: $this->url($input, 'policy_uri'),
            contacts: $this->contacts($input),
            softwareId: $this->text($input, 'software_id', 100),
            softwareVersion: $this->text($input, 'software_version', 100),
            backchannelLogoutUri: $this->backchannelUri($input),
            postLogoutRedirectUris: $this->uriList($input, 'post_logout_redirect_uris'),
        );
    }

    /**
     * @param array<array-key, mixed> $input
     *
     * @return list<GrantType>
     */
    private function grants(array $input): array
    {
        $names = $this->stringList($input, 'grant_types') ?? [GrantType::AuthorizationCode->value];
        $grants = [];
        foreach ($names as $name) {
            $grant = GrantType::tryFrom($name);
            if ($grant === null || !in_array($grant, $this->config->allowedGrantTypes, true)) {
                throw OAuthException::invalidClientMetadata("The grant type {$name} is not supported.");
            }
            $grants[] = $grant;
        }
        if ($grants === []) {
            throw OAuthException::invalidClientMetadata('Name at least one grant type.');
        }
        if (in_array(GrantType::RefreshToken, $grants, true) && count($grants) === 1) {
            throw OAuthException::invalidClientMetadata('The refresh_token grant needs another grant type to get the first token.');
        }

        return array_values(array_unique($grants, SORT_REGULAR));
    }

    /**
     * @param array<array-key, mixed> $input
     *
     * @return list<string>
     */
    private function scopes(array $input): array
    {
        $raw = $this->string($input, 'scope');
        $scopes = $this->config->defaultScopes;
        if ($raw !== null) {
            $scopes = array_values(array_unique(array_filter(explode(' ', $raw), static fn (string $s): bool => $s !== '')));
        }
        foreach ($scopes as $scope) {
            if (!in_array($scope, $this->allowedScopes, true)) {
                throw OAuthException::invalidClientMetadata("The scope {$scope} is not available to registered clients.");
            }
        }

        return $scopes;
    }

    /**
     * @param array<array-key, mixed> $input
     *
     * @return list<string>
     */
    private function redirectUris(array $input, bool $required): array
    {
        $uris = $this->uriList($input, 'redirect_uris');
        if ($required && $uris === []) {
            throw OAuthException::invalidRedirectUri('A client that uses the authorization code grant needs redirect_uris.');
        }

        return $uris;
    }

    /**
     * @param array<array-key, mixed> $input
     *
     * @return list<string>
     */
    private function uriList(array $input, string $field): array
    {
        $uris = $this->stringList($input, $field) ?? [];
        if (count($uris) > $this->config->maxRedirectUris) {
            throw OAuthException::invalidClientMetadata("{$field} may hold at most {$this->config->maxRedirectUris} URIs.");
        }
        foreach ($uris as $uri) {
            $this->assertRedirectUri($uri);
        }

        return array_values(array_unique($uris));
    }

    private function assertRedirectUri(string $uri): void
    {
        $parts = strlen($uri) <= 2048 && preg_match('/[\x00-\x20\x7F]/', $uri) !== 1 ? parse_url($uri) : false;
        if ($parts === false || !isset($parts['scheme']) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            throw OAuthException::invalidRedirectUri("The redirect URI {$this->short($uri)} must be an absolute URI without a fragment or credentials.");
        }
        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host'] ?? '');

        if ($scheme === 'https') {
            if ($host === '') {
                throw OAuthException::invalidRedirectUri("The redirect URI {$this->short($uri)} needs a host.");
            }

            return;
        }
        if ($scheme === 'http') {
            if (!in_array($host, ['localhost', '127.0.0.1', '[::1]'], true)) {
                throw OAuthException::invalidRedirectUri('Redirect URIs must use https; http is only accepted for localhost, 127.0.0.1 and [::1].');
            }

            return;
        }
        if (!$this->config->allowCustomSchemeRedirects || in_array($scheme, self::DANGEROUS_SCHEMES, true)) {
            throw OAuthException::invalidRedirectUri("The scheme {$scheme} is not accepted in a redirect URI.");
        }
    }

    /** @param array<array-key, mixed> $input */
    private function backchannelUri(array $input): ?string
    {
        $uri = $this->url($input, 'backchannel_logout_uri');
        if ($uri === null) {
            return null;
        }
        $host = strtolower((string) parse_url($uri, PHP_URL_HOST));
        if ($host === 'localhost' || str_starts_with($host, '[') || filter_var($host, FILTER_VALIDATE_IP) !== false) {
            throw OAuthException::invalidClientMetadata('The backchannel_logout_uri must name a host, not an IP address or localhost.');
        }

        return $uri;
    }

    /**
     * @param array<array-key, mixed> $input
     *
     * @return list<string>
     */
    private function contacts(array $input): array
    {
        $contacts = $this->stringList($input, 'contacts') ?? [];
        if (count($contacts) > 10) {
            throw OAuthException::invalidClientMetadata('contacts may hold at most 10 entries.');
        }
        foreach ($contacts as $contact) {
            if (strlen($contact) > 254 || preg_match('/[\x00-\x1F\x7F]/', $contact) === 1) {
                throw OAuthException::invalidClientMetadata('A contact is too long or contains control characters.');
            }
        }

        return $contacts;
    }

    /** @param array<array-key, mixed> $input */
    private function url(array $input, string $field): ?string
    {
        $value = $this->string($input, $field);
        if ($value === null) {
            return null;
        }
        $parts = strlen($value) <= 2048 && preg_match('/[\x00-\x20\x7F]/', $value) !== 1 ? parse_url($value) : false;
        if ($parts === false || strtolower($parts['scheme'] ?? '') !== 'https' || ($parts['host'] ?? '') === '' || isset($parts['user']) || isset($parts['pass'])) {
            throw OAuthException::invalidClientMetadata("The {$field} must be an https URL.");
        }

        return $value;
    }

    /** @param array<array-key, mixed> $input */
    private function text(array $input, string $field, int $max): ?string
    {
        $value = $this->string($input, $field);
        if ($value !== null && (mb_strlen($value) > $max || preg_match('/[\x00-\x1F\x7F]/', $value) === 1)) {
            throw OAuthException::invalidClientMetadata("The {$field} is too long or contains control characters.");
        }

        return $value;
    }

    /** @param array<array-key, mixed> $input */
    private function string(array $input, string $field): ?string
    {
        $value = $input[$field] ?? null;
        if ($value === null) {
            return null;
        }
        if (!is_string($value)) {
            throw OAuthException::invalidClientMetadata("The {$field} must be a string.");
        }

        return $value === '' ? null : $value;
    }

    /**
     * @param array<array-key, mixed> $input
     *
     * @return list<string>|null
     */
    private function stringList(array $input, string $field): ?array
    {
        $value = $input[$field] ?? null;
        if ($value === null) {
            return null;
        }
        if (!is_array($value) || !array_is_list($value)) {
            throw OAuthException::invalidClientMetadata("The {$field} must be an array of strings.");
        }
        foreach ($value as $item) {
            if (!is_string($item) || $item === '') {
                throw OAuthException::invalidClientMetadata("The {$field} must be an array of strings.");
            }
        }

        return $value;
    }

    private function short(string $uri): string
    {
        return strlen($uri) > 60 ? substr($uri, 0, 57) . '...' : $uri;
    }
}
