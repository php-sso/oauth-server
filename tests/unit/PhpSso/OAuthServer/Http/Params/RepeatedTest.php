<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Http\Params;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\Params;

#[CoversMethod(Params::class, 'repeated')]
final class RepeatedTest extends TestCase
{
    public function testItReadsEveryRepeatedValueOfTheQuery(): void
    {
        // Arrange
        $request = (new ServerRequest([], [], 'https://sso.example.com/authorize?resource=https%3A%2F%2Fa.example&x=1&resource=https%3A%2F%2Fb.example%2Fapi'))
            ->withQueryParams(['resource' => 'https://b.example/api', 'x' => '1']);

        // Act
        $values = Params::fromQuery($request)->repeated('resource');

        // Assert
        self::assertSame(['https://a.example', 'https://b.example/api'], $values);
    }

    public function testItReadsEveryRepeatedValueOfAFormBody(): void
    {
        // Arrange
        $request = (new ServerRequest([], [], '/token', 'POST'))->withParsedBody(['resource' => 'b']);
        $stream = new \Laminas\Diactoros\Stream('php://memory', 'wb+');
        $stream->write('grant_type=x&resource=a&resource=b');
        $request = $request->withBody($stream);

        // Act
        $values = Params::fromBody($request)->repeated('resource');

        // Assert
        self::assertSame(['a', 'b'], $values);
    }

    public function testItAcceptsAnArrayThatAFrameworkAlreadyCollected(): void
    {
        // Arrange
        $request = (new ServerRequest())->withQueryParams(['resource' => ['a', 'b']]);

        // Act
        $values = Params::fromQuery($request)->repeated('resource');

        // Assert
        self::assertSame(['a', 'b'], $values);
    }

    public function testAMissingParameterIsAnEmptyList(): void
    {
        // Act
        $values = Params::fromQuery(new ServerRequest())->repeated('resource');

        // Assert
        self::assertSame([], $values);
    }

    public function testAnEmptyValueIsAnError(): void
    {
        // Arrange
        $request = (new ServerRequest([], [], 'https://sso.example.com/authorize?resource='))->withQueryParams(['resource' => '']);
        $this->expectException(OAuthException::class);

        // Act
        Params::fromQuery($request)->repeated('resource');
    }
}
