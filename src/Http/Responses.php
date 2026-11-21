<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Http;

use JsonException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use RuntimeException;

/** Builds the few kinds of response the endpoints produce, on whatever PSR-7 implementation the app uses. */
final readonly class Responses
{
    public function __construct(private ResponseFactoryInterface $responses, private StreamFactoryInterface $streams)
    {
    }

    /**
     * @param array<mixed>          $data
     * @param array<string, string> $headers
     */
    public function json(array $data, int $status = 200, array $headers = []): ResponseInterface
    {
        try {
            $body = json_encode($data === [] ? new \stdClass() : $data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new RuntimeException('The response cannot be encoded as JSON.', 0, $e);
        }

        $response = $this->responses->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streams->createStream($body));

        foreach ($headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    /** A response that must never be cached: tokens and errors. */
    public function noStore(ResponseInterface $response): ResponseInterface
    {
        return $response->withHeader('Cache-Control', 'no-store')->withHeader('Pragma', 'no-cache');
    }

    /**
     * Redirects to a URL, adding parameters to its query string and keeping the ones it already has.
     *
     * @param array<string, string> $parameters
     */
    public function redirect(string $url, array $parameters = []): ResponseInterface
    {
        if ($parameters !== []) {
            $url .= (str_contains($url, '?') ? '&' : '?') . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
        }

        return $this->responses->createResponse(302)->withHeader('Location', $url)->withHeader('Cache-Control', 'no-store');
    }
}
