<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Http\JsonErrorResponder;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\JsonErrorResponder;
use PhpSso\OAuthServer\Http\Responses;

#[CoversMethod(JsonErrorResponder::class, 'respond')]
final class RespondTest extends TestCase
{
    private JsonErrorResponder $responder;

    protected function setUp(): void
    {
        $this->responder = new JsonErrorResponder(new Responses(new ResponseFactory(), new StreamFactory()));
    }

    public function testItAnswersWithTheRfcErrorBodyAndStatus(): void
    {
        // Act
        $response = $this->responder->respond(OAuthException::invalidGrant('The code expired.'));

        // Assert
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('{"error":"invalid_grant","error_description":"The code expired."}', (string) $response->getBody());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testItChallengesAClientThatFailedToAuthenticate(): void
    {
        // Act
        $response = $this->responder->respond(OAuthException::invalidClient('Nope.'));

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertStringStartsWith('Basic', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testItChallengesWithBearerForTokenErrorsAndEscapesTheDescription(): void
    {
        // Act
        $response = $this->responder->respond(OAuthException::invalidToken('Say "no" \\ now'));

        // Assert
        self::assertSame('Bearer error="invalid_token", error_description="Say \\"no\\" \\\\ now"', $response->getHeaderLine('WWW-Authenticate'));
    }
}
