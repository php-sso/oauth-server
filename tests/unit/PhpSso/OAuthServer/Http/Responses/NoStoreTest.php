<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Http\Responses;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Http\Responses;

#[CoversMethod(Responses::class, 'noStore')]
final class NoStoreTest extends TestCase
{
    public function testItForbidsCaching(): void
    {
        // Arrange
        $responses = new Responses(new ResponseFactory(), new StreamFactory());

        // Act
        $response = $responses->noStore((new ResponseFactory())->createResponse());

        // Assert
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('no-cache', $response->getHeaderLine('Pragma'));
    }
}
