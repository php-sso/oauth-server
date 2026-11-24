<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Resource\ResourceIndicators;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\Params;
use PhpSso\OAuthServer\Resource\ResourceIndicators;
use PhpSso\OAuthServer\Tests\Support\TestResourcePolicy;

#[CoversMethod(ResourceIndicators::class, 'requested')]
final class RequestedTest extends TestCase
{
    private function params(mixed $resource): Params
    {
        return Params::fromQuery((new ServerRequest())->withQueryParams(['resource' => $resource]));
    }

    public function testItIgnoresTheParameterWithoutAPolicy(): void
    {
        // Arrange
        $indicators = new ResourceIndicators(null);

        // Act
        $resources = $indicators->requested($this->params('https://mcp.example/'));

        // Assert
        self::assertSame([], $resources);
    }

    public function testItKeepsEachResourceOnce(): void
    {
        // Arrange
        $indicators = new ResourceIndicators(new TestResourcePolicy());

        // Act
        $resources = $indicators->requested($this->params(['https://a.example/', 'https://a.example/', 'urn:example:api']));

        // Assert
        self::assertSame(['https://a.example/', 'urn:example:api'], $resources);
    }

    #[DataProvider('malformed')]
    public function testItRefusesAResourceThatIsNotAnAbsoluteUriWithoutAFragment(string $resource): void
    {
        // Arrange
        $indicators = new ResourceIndicators(new TestResourcePolicy());
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('invalid_target');

        // Act
        $indicators->requested($this->params($resource));
    }

    /** @return iterable<string, array{string}> */
    public static function malformed(): iterable
    {
        yield 'relative' => ['/api'];
        yield 'fragment' => ['https://a.example/api#x'];
        yield 'no host' => ['https:///api'];
        yield 'space' => ['https://a.example/a b'];
        yield 'bare word' => ['api'];
    }
}
