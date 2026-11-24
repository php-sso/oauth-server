<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Registration;

use InvalidArgumentException;
use PhpSso\OAuthServer\Grant\GrantType;

/** What dynamic client registration (RFC 7591 and RFC 7592) accepts. The defaults suit applications that sign people in. */
final readonly class RegistrationConfig
{
    /**
     * @param string            $scope                       The scope an access token needs to register a client. Add it to
     *                                                       {@see \PhpSso\OAuthServer\Config\ServerConfig::$scopes} and give it only to the
     *                                                       clients you trust to register others. Registered clients can never hold it.
     * @param list<GrantType>   $allowedGrantTypes           What a registered client may use. Client credentials is left out on purpose:
     *                                                       a client that registers itself should not get a machine identity.
     * @param list<string>      $allowedAuthMethods          `none` (public client), `client_secret_basic` and `client_secret_post`.
     * @param list<string>|null $allowedScopes               What a registered client may ask for; the server's scopes when null.
     * @param list<string>      $defaultScopes               The scopes of a client that does not name any.
     * @param bool              $allowCustomSchemeRedirects  Private-use URI schemes such as `com.example.app:/callback` (RFC 8252), which
     *                                                       native apps use. `javascript:`, `data:`, `file:` and a few more are never accepted.
     * @param int               $maxRedirectUris             The most redirect URIs one client may have.
     */
    public function __construct(
        public string $scope = 'client:register',
        public array $allowedGrantTypes = [GrantType::AuthorizationCode, GrantType::RefreshToken],
        public array $allowedAuthMethods = ['none', 'client_secret_basic', 'client_secret_post'],
        public ?array $allowedScopes = null,
        public array $defaultScopes = ['openid'],
        public bool $allowCustomSchemeRedirects = true,
        public int $maxRedirectUris = 10,
    ) {
        if ($scope === '' || preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scope) !== 1) {
            throw new InvalidArgumentException('The registration scope must be a valid scope name.');
        }
        if ($allowedGrantTypes === [] || $allowedAuthMethods === [] || $maxRedirectUris < 1) {
            throw new InvalidArgumentException('Allow at least one grant type, one authentication method and one redirect URI.');
        }
        foreach ($allowedAuthMethods as $method) {
            if (!in_array($method, ['none', 'client_secret_basic', 'client_secret_post'], true)) {
                throw new InvalidArgumentException("Unsupported token endpoint authentication method: {$method}");
            }
        }
    }
}
