<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Resource\ResourceIndicators;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Resource\ResourceIndicators;
use PhpSso\OAuthServer\Tests\Support\TestClient;
use PhpSso\OAuthServer\Tests\Support\TestResourcePolicy;

#[CoversMethod(ResourceIndicators::class, 'resolve')]
final class ResolveTest extends TestCase
{
    private function client(): TestClient
    {
        return new TestClient('web', [], true, [], []);
    }

    private function indicators(): ResourceIndicators
    {
        return new ResourceIndicators(new TestResourcePolicy(['web' => ['https://a.example', 'https://b.example']]));
    }

    public function testWithoutAPolicyThereAreNoResources(): void
    {
        // Act
        $resources = (new ResourceIndicators(null))->resolve(['https://a.example'], [], $this->client());

        // Assert
        self::assertSame([], $resources);
    }

    public function testWhatWasAskedForIsUsed(): void
    {
        // Act
        $resources = $this->indicators()->resolve(['https://a.example'], [], $this->client());

        // Assert
        self::assertSame(['https://a.example'], $resources);
    }

    public function testWhenNothingIsAskedForTheGrantIsUsed(): void
    {
        // Act
        $resources = $this->indicators()->resolve([], ['https://a.example', 'https://b.example'], $this->client());

        // Assert
        self::assertSame(['https://a.example', 'https://b.example'], $resources);
    }

    public function testARequestMayNarrowTheGrant(): void
    {
        // Act
        $resources = $this->indicators()->resolve(['https://b.example'], ['https://a.example', 'https://b.example'], $this->client());

        // Assert
        self::assertSame(['https://b.example'], $resources);
    }

    public function testARequestMayNotWidenTheGrant(): void
    {
        // Arrange
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('invalid_target');

        // Act
        $this->indicators()->resolve(['https://b.example'], ['https://a.example'], $this->client());
    }

    public function testAResourceTheClientMayNotHaveIsRefused(): void
    {
        // Arrange
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('invalid_target');

        // Act
        $this->indicators()->resolve(['https://evil.example'], [], $this->client());
    }

    public function testAGrantedResourceThatIsNoLongerAllowedIsRefused(): void
    {
        // Arrange
        $indicators = new ResourceIndicators(new TestResourcePolicy(['web' => []]));
        $this->expectException(OAuthException::class);

        // Act
        $indicators->resolve([], ['https://a.example'], $this->client());
    }
}
