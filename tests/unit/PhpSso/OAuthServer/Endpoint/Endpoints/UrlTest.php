<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\Endpoints;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\Endpoints;

#[CoversMethod(Endpoints::class, 'url')]
final class UrlTest extends TestCase
{
    public function testItResolvesAPathAgainstTheIssuer(): void
    {
        // Act
        $url = Endpoints::url('https://sso.example.com', '/token');

        // Assert
        self::assertSame('https://sso.example.com/token', $url);
    }

    public function testItUsesAnAbsoluteUrlAsItIs(): void
    {
        // Act
        $url = Endpoints::url('https://sso.example.com', 'https://other.example/oauth/token');

        // Assert
        self::assertSame('https://other.example/oauth/token', $url);
    }
}
