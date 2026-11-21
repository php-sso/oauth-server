<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryAuthorizationCodeStore;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\AuthorizationCodeRecord;
use PhpSso\OAuthServer\InMemory\InMemoryAuthorizationCodeStore;

#[CoversMethod(InMemoryAuthorizationCodeStore::class, 'find')]
final class FindTest extends TestCase
{
    public function testItFindsASavedCodeByItsHash(): void
    {
        // Arrange
        $store = new InMemoryAuthorizationCodeStore();
        $code = $this->code();
        $store->save($code);

        // Act
        $found = $store->find('hash-1');

        // Assert
        self::assertSame($code, $found);
    }

    public function testItReturnsNullForAnUnknownCode(): void
    {
        // Arrange
        $store = new InMemoryAuthorizationCodeStore();

        // Act
        $found = $store->find('nope');

        // Assert
        self::assertNull($found);
    }

    private function code(string $hash = 'hash-1'): AuthorizationCodeRecord
    {
        return new AuthorizationCodeRecord($hash, 'client-1', 'user-1', 'https://app/cb', ['openid'], str_repeat('c', 43), 'nonce-1', 'session-1', 'family-1', 1_700_000_060, null, null);
    }
}
