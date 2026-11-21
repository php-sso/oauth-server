<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Http\Responses;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Http\Responses;

#[CoversMethod(Responses::class, 'json')]
final class JsonTest extends TestCase
{
    public function testItBuildsAJsonResponse(): void
    {
        // Arrange
        $responses = new Responses(new ResponseFactory(), new StreamFactory());

        // Act
        $response = $responses->json(['a' => 1], 201, ['X-Test' => 'yes']);

        // Assert
        self::assertSame(201, $response->getStatusCode());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame('yes', $response->getHeaderLine('X-Test'));
        self::assertSame('{"a":1}', (string) $response->getBody());
    }

    public function testItEncodesAnEmptyArrayAsAnObject(): void
    {
        // Arrange
        $responses = new Responses(new ResponseFactory(), new StreamFactory());

        // Act
        $response = $responses->json([]);

        // Assert
        self::assertSame('{}', (string) $response->getBody());
    }
}
