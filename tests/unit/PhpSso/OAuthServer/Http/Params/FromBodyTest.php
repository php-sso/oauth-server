<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Http\Params;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Http\Params;

#[CoversMethod(Params::class, 'fromBody')]
final class FromBodyTest extends TestCase
{
    public function testItUsesTheBodyAFrameworkAlreadyParsed(): void
    {
        // Arrange
        $request = (new ServerRequest())->withParsedBody(['grant_type' => 'refresh_token']);

        // Act
        $params = Params::fromBody($request);

        // Assert
        self::assertSame('refresh_token', $params->string('grant_type'));
    }

    public function testItDecodesTheRawFormWhenNothingParsedIt(): void
    {
        // Arrange
        $request = (new ServerRequest())->withBody((new StreamFactory())->createStream('grant_type=refresh_token&scope=a+b'));

        // Act
        $params = Params::fromBody($request);

        // Assert
        self::assertSame('refresh_token', $params->string('grant_type'));
        self::assertSame('a b', $params->string('scope'));
    }
}
