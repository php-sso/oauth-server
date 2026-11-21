<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'toArray')]
final class ToArrayTest extends TestCase
{
    public function testItProducesTheJsonBodyOfAnErrorResponse(): void
    {
        // Arrange
        $exception = OAuthException::invalidGrant('The code expired.');

        // Act
        $body = $exception->toArray();

        // Assert
        self::assertSame(['error' => 'invalid_grant', 'error_description' => 'The code expired.'], $body);
    }
}
