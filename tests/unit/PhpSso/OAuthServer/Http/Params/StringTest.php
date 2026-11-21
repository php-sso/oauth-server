<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Http\Params;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\Params;

#[CoversMethod(Params::class, 'string')]
final class StringTest extends TestCase
{
    public function testItReturnsAParameterAsAString(): void
    {
        // Arrange
        $params = Params::fromQuery((new ServerRequest())->withQueryParams(['a' => 'x']));

        // Act
        $value = $params->string('a');

        // Assert
        self::assertSame('x', $value);
    }

    public function testItTreatsMissingAndEmptyParametersAsAbsent(): void
    {
        // Arrange
        $params = Params::fromQuery((new ServerRequest())->withQueryParams(['empty' => '']));

        // Act
        $missing = $params->string('nope');
        $empty = $params->string('empty');

        // Assert
        self::assertNull($missing);
        self::assertNull($empty);
    }

    public function testItRejectsAParameterGivenAsAnArray(): void
    {
        // Arrange
        $params = Params::fromQuery((new ServerRequest())->withQueryParams(['a' => ['x', 'y']]));
        $this->expectException(OAuthException::class);

        // Act
        $params->string('a');
    }
}
