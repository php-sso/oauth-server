<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Config\ServerConfig;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Config\ServerConfig;

#[CoversMethod(ServerConfig::class, '__construct')]
final class __constructTest extends TestCase
{
    public function testItAcceptsAValidConfiguration(): void
    {
        // Act
        $config = new ServerConfig('https://sso.example.com', ['openid', 'email']);

        // Assert
        self::assertSame('https://sso.example.com', $config->issuer);
        self::assertSame(['openid', 'email'], $config->scopes);
    }

    /** @param list<string> $scopes */
    #[DataProvider('invalidSettings')]
    public function testItRejectsInvalidSettings(string $issuer, array $scopes, int $codeTtl): void
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);

        // Act
        new ServerConfig($issuer, $scopes, authorizationCodeTtl: $codeTtl);
    }

    /** @return array<string, array{string, list<string>, int}> */
    public static function invalidSettings(): array
    {
        return [
            'issuer without scheme' => ['sso.example.com', ['openid'], 60],
            'issuer with trailing slash' => ['https://sso.example.com/', ['openid'], 60],
            'no scopes' => ['https://sso.example.com', [], 60],
            'duplicate scopes' => ['https://sso.example.com', ['openid', 'openid'], 60],
            'scope with a space' => ['https://sso.example.com', ['open id'], 60],
            'empty scope' => ['https://sso.example.com', [''], 60],
            'zero lifetime' => ['https://sso.example.com', ['openid'], 0],
        ];
    }
}
