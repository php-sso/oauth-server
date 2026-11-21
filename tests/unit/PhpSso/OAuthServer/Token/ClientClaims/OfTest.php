<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Token\ClientClaims;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Authorization\UserClaimsProvider;
use PhpSso\OAuthServer\Tests\Support\TestClaimsProvider;
use PhpSso\OAuthServer\Token\ClientClaims;

#[CoversMethod(ClientClaims::class, 'of')]
final class OfTest extends TestCase
{
    public function testItReturnsTheClaimsTheProviderReleasesToTheClient(): void
    {
        // Arrange
        $provider = new TestClaimsProvider();
        $provider->clientClaims['web'] = ['roles' => ['editor']];

        // Act
        $claims = ClientClaims::of($provider, 'web', 'user-1', ['openid']);

        // Assert
        self::assertSame(['roles' => ['editor']], $claims);
    }

    public function testItAsksForTheClientThePersonAndTheScopes(): void
    {
        // Arrange
        $provider = new TestClaimsProvider();

        // Act
        ClientClaims::of($provider, 'web', 'user-1', ['openid', 'roles']);

        // Assert
        self::assertSame([['client' => 'web', 'user' => 'user-1', 'scopes' => ['openid', 'roles']]], $provider->clientClaimRequests);
    }

    public function testItDropsTheClaimsTheLibraryControls(): void
    {
        // Arrange
        $provider = new TestClaimsProvider();
        $provider->clientClaims['web'] = ['roles' => ['editor'], 'sub' => 'forged', 'aud' => 'x', 'exp' => 1];

        // Act
        $claims = ClientClaims::of($provider, 'web', 'user-1', ['openid']);

        // Assert
        self::assertSame(['roles' => ['editor']], $claims);
    }

    public function testItReturnsNothingForAProviderThatDoesNotKnowAboutClients(): void
    {
        // Arrange
        $provider = new class implements UserClaimsProvider {
            public function claimsFor(string $userId, array $scopes): array
            {
                return ['name' => 'Alice'];
            }
        };

        // Act
        $claims = ClientClaims::of($provider, 'web', 'user-1', ['openid']);

        // Assert
        self::assertSame([], $claims);
    }
}
