<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryAuthorizationCodeStore;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\AuthorizationCodeRecord;
use PhpSso\OAuthServer\InMemory\InMemoryAuthorizationCodeStore;

#[CoversMethod(InMemoryAuthorizationCodeStore::class, 'save')]
final class SaveTest extends TestCase
{
    public function testItReplacesACodeSavedUnderTheSameHash(): void
    {
        // Arrange
        $store = new InMemoryAuthorizationCodeStore();
        $store->save($this->code());
        $replacement = new AuthorizationCodeRecord('hash-1', 'client-2', 'user-2', 'https://other/cb', [], str_repeat('d', 43), null, null, 'family-2', 1_700_000_090, null, null);

        // Act
        $store->save($replacement);

        // Assert
        self::assertSame($replacement, $store->find('hash-1'));
    }

    private function code(string $hash = 'hash-1'): AuthorizationCodeRecord
    {
        return new AuthorizationCodeRecord($hash, 'client-1', 'user-1', 'https://app/cb', ['openid'], str_repeat('c', 43), 'nonce-1', 'session-1', 'family-1', 1_700_000_060, null, null);
    }
}
