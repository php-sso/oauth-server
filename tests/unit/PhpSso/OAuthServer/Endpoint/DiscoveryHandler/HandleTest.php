<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\DiscoveryHandler;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\DiscoveryHandler;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(DiscoveryHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    public function testItDescribesTheServer(): void
    {
        // Arrange
        $t = new TestServer();

        // Act
        $metadata = $t->json($t->server->discoveryHandler()->handle(new ServerRequest()));

        // Assert
        self::assertSame('https://sso.example.com', $metadata['issuer']);
        self::assertSame('https://sso.example.com/authorize', $metadata['authorization_endpoint']);
        self::assertSame('https://sso.example.com/token', $metadata['token_endpoint']);
        self::assertSame('https://sso.example.com/userinfo', $metadata['userinfo_endpoint']);
        self::assertSame('https://sso.example.com/jwks', $metadata['jwks_uri']);
        self::assertSame('https://sso.example.com/device_authorization', $metadata['device_authorization_endpoint']);
        self::assertSame(['code'], $metadata['response_types_supported']);
        self::assertSame(['S256'], $metadata['code_challenge_methods_supported']);
        self::assertSame(['RS256'], $metadata['id_token_signing_alg_values_supported']);
        self::assertSame(['openid', 'profile', 'email', 'api', 'client:register'], $metadata['scopes_supported']);
    }

    public function testItAdvertisesBackChannelLogoutAndNoFrontChannelLogout(): void
    {
        // Arrange
        $t = new TestServer();

        // Act
        $metadata = $t->json($t->server->discoveryHandler()->handle(new ServerRequest()));

        // Assert
        self::assertTrue($metadata['backchannel_logout_supported']);
        self::assertTrue($metadata['backchannel_logout_session_supported']);
        self::assertFalse($metadata['frontchannel_logout_supported']);
    }

    public function testItListsTheRevocationAndIntrospectionEndpointsWhenConfigured(): void
    {
        // Arrange
        $t = new TestServer();

        // Act
        $metadata = $t->json($t->server->discoveryHandler()->handle(new ServerRequest()));

        // Assert
        self::assertSame('https://sso.example.com/revoke', $metadata['revocation_endpoint']);
        self::assertSame('https://sso.example.com/introspect', $metadata['introspection_endpoint']);
        self::assertSame(['client_secret_basic', 'client_secret_post'], $metadata['introspection_endpoint_auth_methods_supported']);
    }

    public function testItListsTheEndSessionAndDeviceEndpoints(): void
    {
        // Arrange
        $t = new TestServer();

        // Act
        $metadata = $t->json($t->server->discoveryHandler()->handle(new ServerRequest()));

        // Assert
        self::assertSame('https://sso.example.com/end-session', $metadata['end_session_endpoint']);
        self::assertSame('https://sso.example.com/device_authorization', $metadata['device_authorization_endpoint']);
    }

    public function testItAdvertisesOnlyTheGrantsItImplements(): void
    {
        // Arrange
        $t = new TestServer();

        // Act
        $metadata = $t->json($t->server->discoveryHandler()->handle(new ServerRequest()));

        // Assert
        self::assertSame(
            ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
            $metadata['grant_types_supported'],
        );
    }

    public function testItAdvertisesTheRegistrationEndpointWhenRegistrationIsOn(): void
    {
        // Arrange
        $t = new TestServer();

        // Act
        $metadata = $t->json($t->server->discoveryHandler()->handle(new ServerRequest()));

        // Assert
        self::assertSame('https://sso.example.com/register', $metadata['registration_endpoint']);
    }

    public function testItLeavesOutTheRegistrationEndpointWhenRegistrationIsOff(): void
    {
        // Arrange
        $t = new TestServer(registration: false);

        // Act
        $metadata = $t->json($t->server->discoveryHandler()->handle(new ServerRequest()));

        // Assert
        self::assertArrayNotHasKey('registration_endpoint', $metadata);
    }
}
