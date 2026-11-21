<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryAuthorizationCodeStore;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\AuthorizationCodeRecord;
use PhpSso\OAuthServer\InMemory\InMemoryAuthorizationCodeStore;

#[CoversMethod(InMemoryAuthorizationCodeStore::class, 'markUsed')]
final class MarkUsedTest extends TestCase
{
    public function testItMarksAnUnusedCodeAsUsedOnce(): void
    {
        // Arrange
        $store = new InMemoryAuthorizationCodeStore();
        $store->save($this->code());

        // Act
        $first = $store->markUsed('hash-1', 1_700_000_010);
        $second = $store->markUsed('hash-1', 1_700_000_011);

        // Assert
        self::assertTrue($first);
        self::assertFalse($second);
        self::assertSame(1_700_000_010, $store->find('hash-1')?->usedAt);
    }

    public function testItKeepsTheRestOfTheRecordWhenMarkingItUsed(): void
    {
        // Arrange
        $store = new InMemoryAuthorizationCodeStore();
        $store->save($this->code());

        // Act
        $store->markUsed('hash-1', 1_700_000_010);

        // Assert
        $record = $store->find('hash-1');
        self::assertSame('family-1', $record?->familyId);
        self::assertSame('session-1', $record->sessionId);
        self::assertSame('nonce-1', $record->nonce);
    }

    public function testItRefusesAnUnknownCode(): void
    {
        // Arrange
        $store = new InMemoryAuthorizationCodeStore();

        // Act
        $result = $store->markUsed('nope', 1_700_000_010);

        // Assert
        self::assertFalse($result);
    }

    private function code(string $hash = 'hash-1'): AuthorizationCodeRecord
    {
        return new AuthorizationCodeRecord($hash, 'client-1', 'user-1', 'https://app/cb', ['openid'], str_repeat('c', 43), 'nonce-1', 'session-1', 'family-1', 1_700_000_060, null, null);
    }
}
