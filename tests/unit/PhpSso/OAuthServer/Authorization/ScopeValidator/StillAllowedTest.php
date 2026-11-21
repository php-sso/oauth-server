<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Authorization\ScopeValidator;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Authorization\ScopeValidator;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Tests\Support\TestClient;

#[CoversMethod(ScopeValidator::class, 'stillAllowed')]
final class StillAllowedTest extends TestCase
{
    public function testAScopeTheServerNoLongerOffersIsDropped(): void
    {
        // Arrange
        $validator = new ScopeValidator(new ServerConfig('https://sso.example.com', ['openid', 'email']));
        $client = new TestClient('web', [], true, [], ['openid', 'profile', 'email']);

        // Act
        $kept = $validator->stillAllowed($client, ['openid', 'profile', 'email']);

        // Assert
        self::assertSame(['openid', 'email'], $kept);
    }

    public function testAScopeTheClientMayNoLongerAskForIsDropped(): void
    {
        // Arrange
        $validator = new ScopeValidator(new ServerConfig('https://sso.example.com', ['openid', 'email', 'api']));
        $client = new TestClient('web', [], true, [], ['openid', 'email']);

        // Act
        $kept = $validator->stillAllowed($client, ['api', 'openid', 'email']);

        // Assert
        self::assertSame(['openid', 'email'], $kept);
    }

    public function testNothingIsDroppedWhenEverythingIsStillAllowedAndTheOrderIsKept(): void
    {
        // Arrange
        $validator = new ScopeValidator(new ServerConfig('https://sso.example.com', ['openid', 'email']));
        $client = new TestClient('web', [], true, [], ['openid', 'email']);

        // Act
        $kept = $validator->stillAllowed($client, ['email', 'openid']);

        // Assert
        self::assertSame(['email', 'openid'], $kept);
    }

    public function testWhenNothingIsLeftTheListIsEmpty(): void
    {
        // Arrange
        $validator = new ScopeValidator(new ServerConfig('https://sso.example.com', ['openid']));
        $client = new TestClient('web', [], true, [], ['email']);

        // Act
        $kept = $validator->stillAllowed($client, ['openid', 'email']);

        // Assert
        self::assertSame([], $kept);
    }
}
