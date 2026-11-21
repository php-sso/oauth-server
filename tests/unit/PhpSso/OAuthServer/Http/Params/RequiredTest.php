<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Http\Params;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\Params;

#[CoversMethod(Params::class, 'required')]
final class RequiredTest extends TestCase
{
    public function testItReturnsAPresentParameter(): void
    {
        // Arrange
        $params = Params::fromQuery((new ServerRequest())->withQueryParams(['a' => 'x']));

        // Act
        $value = $params->required('a');

        // Assert
        self::assertSame('x', $value);
    }

    public function testItRejectsAMissingParameter(): void
    {
        // Arrange
        $params = Params::fromQuery(new ServerRequest());
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('invalid_request');

        // Act
        $params->required('a');
    }
}
