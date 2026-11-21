<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use Laminas\Diactoros\Response;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/** A PSR-18 client that records what was sent and answers as told, per URL. */
final class FakeHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $sent = [];

    /** @var array<string, int|string> status per URL; a string makes the request fail with that message */
    public array $answers = [];

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->sent[] = $request;
        $answer = $this->answers[(string) $request->getUri()] ?? 200;
        if (is_string($answer)) {
            throw new class($answer) extends RuntimeException implements ClientExceptionInterface {
            };
        }

        return (new Response())->withStatus($answer);
    }

    /** The logout token sent in a request body. */
    public function logoutToken(RequestInterface $request): string
    {
        parse_str((string) $request->getBody(), $form);
        $token = $form['logout_token'] ?? null;
        \assert(is_string($token));

        return $token;
    }
}
