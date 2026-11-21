<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Config\ServerConfig;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Config\ServerConfig;

#[CoversMethod(ServerConfig::class, 'supportsScope')]
final class SupportsScopeTest extends TestCase
{
    public function testItKnowsWhichScopesAreOffered(): void
    {
        // Arrange
        $config = new ServerConfig('https://sso.example.com', ['openid', 'email']);

        // Act
        $known = $config->supportsScope('email');
        $unknown = $config->supportsScope('admin');

        // Assert
        self::assertTrue($known);
        self::assertFalse($unknown);
    }
}
