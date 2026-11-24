<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Registration\ClientMetadataValidator;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Registration\ClientMetadataValidator;
use PhpSso\OAuthServer\Registration\RegistrationConfig;

#[CoversMethod(ClientMetadataValidator::class, 'validate')]
final class ValidateTest extends TestCase
{
    private ClientMetadataValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new ClientMetadataValidator(
            new ServerConfig('https://sso.example.com', ['openid', 'profile', 'email', 'client:register']),
            new RegistrationConfig(),
        );
    }

    public function testItAppliesTheDefaults(): void
    {
        // Act
        $metadata = $this->validator->validate(['redirect_uris' => ['https://app.example/cb']]);

        // Assert
        self::assertSame('client_secret_basic', $metadata->tokenEndpointAuthMethod);
        self::assertSame([GrantType::AuthorizationCode], $metadata->grantTypes);
        self::assertSame(['code'], $metadata->responseTypes);
        self::assertSame(['openid'], $metadata->scopes);
        self::assertTrue($metadata->isConfidential());
    }

    public function testItIgnoresFieldsItDoesNotKnow(): void
    {
        // Act
        $metadata = $this->validator->validate(['redirect_uris' => ['https://app.example/cb'], 'application_type' => 'web', 'x' => ['y']]);

        // Assert
        self::assertSame(['https://app.example/cb'], $metadata->redirectUris);
    }

    /** @param list<string> $uris */
    #[DataProvider('acceptedRedirectUris')]
    public function testItAcceptsSafeRedirectUris(array $uris): void
    {
        // Act
        $metadata = $this->validator->validate(['redirect_uris' => $uris]);

        // Assert
        self::assertSame($uris, $metadata->redirectUris);
    }

    /** @return iterable<string, array{list<string>}> */
    public static function acceptedRedirectUris(): iterable
    {
        yield 'https' => [['https://app.example/cb']];
        yield 'loopback with a port' => [['http://127.0.0.1:8123/callback']];
        yield 'localhost' => [['http://localhost/cb']];
        yield 'ipv6 loopback' => [['http://[::1]:9/cb']];
        yield 'private-use scheme' => [['com.example.app:/callback']];
    }

    #[DataProvider('rejectedRedirectUris')]
    public function testItRejectsUnsafeRedirectUris(string $uri): void
    {
        // Arrange
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('invalid_redirect_uri');

        // Act
        $this->validator->validate(['redirect_uris' => [$uri]]);
    }

    /** @return iterable<string, array{string}> */
    public static function rejectedRedirectUris(): iterable
    {
        yield 'plain http' => ['http://app.example/cb'];
        yield 'fragment' => ['https://app.example/cb#x'];
        yield 'credentials' => ['https://user:pw@app.example/cb'];
        yield 'relative' => ['/cb'];
        yield 'javascript' => ['javascript:alert(1)'];
        yield 'data' => ['data:text/html,x'];
        yield 'space' => ['https://app.example/a b'];
        yield 'no host' => ['https:///cb'];
    }

    public function testRedirectUrisAreRequiredForTheAuthorizationCodeGrant(): void
    {
        // Arrange
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('invalid_redirect_uri');

        // Act
        $this->validator->validate(['token_endpoint_auth_method' => 'none']);
    }

    public function testItRejectsTooManyRedirectUris(): void
    {
        // Arrange
        $uris = array_map(static fn (int $i): string => "https://app.example/cb{$i}", range(1, 11));
        $this->expectException(OAuthException::class);

        // Act
        $this->validator->validate(['redirect_uris' => $uris]);
    }

    /** @param array<string, mixed> $input */
    #[DataProvider('invalidMetadata')]
    public function testItRejectsMetadataItDoesNotAccept(array $input): void
    {
        // Arrange
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('invalid_client_metadata');

        // Act
        $this->validator->validate($input + ['redirect_uris' => ['https://app.example/cb']]);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function invalidMetadata(): iterable
    {
        yield 'client credentials grant' => [['grant_types' => ['client_credentials']]];
        yield 'unknown grant' => [['grant_types' => ['password']]];
        yield 'refresh token alone' => [['grant_types' => ['refresh_token']]];
        yield 'implicit response type' => [['response_types' => ['token']]];
        yield 'code grant without code type' => [['response_types' => []]];
        yield 'private_key_jwt' => [['token_endpoint_auth_method' => 'private_key_jwt']];
        yield 'scope the server lacks' => [['scope' => 'openid admin']];
        yield 'the registration scope' => [['scope' => 'client:register']];
        yield 'scope not a string' => [['scope' => ['openid']]];
        yield 'http logo' => [['logo_uri' => 'http://app.example/logo.png']];
        yield 'javascript client uri' => [['client_uri' => 'javascript:alert(1)']];
        yield 'long name' => [['client_name' => str_repeat('a', 101)]];
        yield 'control characters in name' => [['client_name' => "a\nb"]];
        yield 'contacts not a list' => [['contacts' => 'me@example.com']];
        yield 'http backchannel uri' => [['backchannel_logout_uri' => 'http://app.example/logout']];
        yield 'backchannel to an ip' => [['backchannel_logout_uri' => 'https://10.0.0.1/logout']];
        yield 'backchannel to localhost' => [['backchannel_logout_uri' => 'https://localhost/logout']];
    }

    public function testItAcceptsTheAuthorizationCodeAndRefreshGrantsTogether(): void
    {
        // Act
        $metadata = $this->validator->validate([
            'redirect_uris' => ['https://app.example/cb'], 'grant_types' => ['authorization_code', 'refresh_token'],
            'scope' => 'openid profile', 'token_endpoint_auth_method' => 'none',
            'backchannel_logout_uri' => 'https://app.example/logout', 'post_logout_redirect_uris' => ['https://app.example/bye'],
        ]);

        // Assert
        self::assertSame([GrantType::AuthorizationCode, GrantType::RefreshToken], $metadata->grantTypes);
        self::assertSame(['openid', 'profile'], $metadata->scopes);
        self::assertSame('https://app.example/logout', $metadata->backchannelLogoutUri);
        self::assertSame(['https://app.example/bye'], $metadata->postLogoutRedirectUris);
    }

    public function testCustomSchemesCanBeSwitchedOff(): void
    {
        // Arrange
        $validator = new ClientMetadataValidator(new ServerConfig('https://sso.example.com'), new RegistrationConfig(allowCustomSchemeRedirects: false));
        $this->expectException(OAuthException::class);

        // Act
        $validator->validate(['redirect_uris' => ['com.example.app:/cb']]);
    }
}
