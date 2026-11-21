<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\JwksHandler;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\JwksHandler;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(JwksHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    public function testItPublishesThePublicKeysAndNothingSecret(): void
    {
        // Arrange
        $t = new TestServer();

        // Act
        $response = $t->server->jwksHandler()->handle(new ServerRequest());

        // Assert
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('public, max-age=300', $response->getHeaderLine('Cache-Control'));
        $body = (string) $response->getBody();
        self::assertStringContainsString('"kid":"key-1"', $body);
        self::assertStringNotContainsString('"d":', $body);
        self::assertStringNotContainsString('PRIVATE', $body);
    }
}
