<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Grant;

/**
 * The grant types this server implements. The password grant and the implicit flow are left out on
 * purpose: the OAuth 2.0 Security BCP and OAuth 2.1 removed them.
 */
enum GrantType: string
{
    case AuthorizationCode = 'authorization_code';
    case RefreshToken = 'refresh_token';
    case ClientCredentials = 'client_credentials';
    case DeviceCode = 'urn:ietf:params:oauth:grant-type:device_code';
}
