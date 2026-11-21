<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Http\Responses;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Http\Responses;

#[CoversMethod(Responses::class, 'redirect')]
final class RedirectTest extends TestCase
{
    public function testItAddsParametersToTheQueryString(): void
    {
        // Arrange
        $responses = new Responses(new ResponseFactory(), new StreamFactory());

        // Act
        $response = $responses->redirect('https://app.example/cb', ['code' => 'a b', 'state' => 'x&y']);

        // Assert
        self::assertSame(302, $response->getStatusCode());
        self::assertSame('https://app.example/cb?code=a%20b&state=x%26y', $response->getHeaderLine('Location'));
    }

    public function testItKeepsAQueryStringTheUrlAlreadyHas(): void
    {
        // Arrange
        $responses = new Responses(new ResponseFactory(), new StreamFactory());

        // Act
        $response = $responses->redirect('https://app.example/cb?tenant=a', ['code' => 'c']);

        // Assert
        self::assertSame('https://app.example/cb?tenant=a&code=c', $response->getHeaderLine('Location'));
    }

    public function testItLeavesTheUrlAloneWithoutParameters(): void
    {
        // Arrange
        $responses = new Responses(new ResponseFactory(), new StreamFactory());

        // Act
        $response = $responses->redirect('https://app.example/cb');

        // Assert
        self::assertSame('https://app.example/cb', $response->getHeaderLine('Location'));
    }
}
