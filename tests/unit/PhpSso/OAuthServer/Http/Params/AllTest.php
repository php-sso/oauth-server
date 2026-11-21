<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Http\Params;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Http\Params;

#[CoversMethod(Params::class, 'all')]
final class AllTest extends TestCase
{
    public function testItReturnsEverySingleValuedNonEmptyParameter(): void
    {
        // Arrange
        $params = Params::fromQuery((new ServerRequest())->withQueryParams(['a' => 'x', 'empty' => '', 'list' => ['1', '2'], 'b' => 'y']));

        // Act
        $all = $params->all();

        // Assert
        self::assertSame(['a' => 'x', 'b' => 'y'], $all);
    }
}
