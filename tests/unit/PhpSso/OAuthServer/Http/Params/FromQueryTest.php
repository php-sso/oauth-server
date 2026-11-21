<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Http\Params;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Http\Params;

#[CoversMethod(Params::class, 'fromQuery')]
final class FromQueryTest extends TestCase
{
    public function testItReadsTheQueryString(): void
    {
        // Arrange
        $request = (new ServerRequest())->withQueryParams(['client_id' => 'web'])->withParsedBody(['client_id' => 'ignored']);

        // Act
        $params = Params::fromQuery($request);

        // Assert
        self::assertSame('web', $params->string('client_id'));
    }
}
