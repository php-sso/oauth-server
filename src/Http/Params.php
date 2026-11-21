<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Http;

use PhpSso\OAuthServer\Exception\OAuthException;
use Psr\Http\Message\ServerRequestInterface;

/** The parameters of an OAuth request, read as strings. A parameter given as an array is an error. */
final readonly class Params
{
    /** @param array<array-key, mixed> $values */
    private function __construct(private array $values)
    {
    }

    public static function fromQuery(ServerRequestInterface $request): self
    {
        return new self($request->getQueryParams());
    }

    /** The form body. Uses the parsed body when a framework already decoded it, and decodes the raw form otherwise. */
    public static function fromBody(ServerRequestInterface $request): self
    {
        $parsed = $request->getParsedBody();
        if (is_array($parsed)) {
            return new self($parsed);
        }

        $values = [];
        parse_str((string) $request->getBody(), $values);

        return new self($values);
    }

    /**
     * Every single-valued, non-empty parameter. Arrays are left out.
     *
     * @return array<string, string>
     */
    public function all(): array
    {
        $strings = [];
        foreach ($this->values as $name => $value) {
            if (is_string($value) && $value !== '') {
                $strings[(string) $name] = $value;
            }
        }

        return $strings;
    }

    /** The value, or null when the parameter is missing or empty. */
    public function string(string $name): ?string
    {
        $value = $this->values[$name] ?? null;
        if ($value === null || $value === '') {
            return null;
        }
        if (!is_string($value)) {
            throw OAuthException::invalidRequest("The {$name} parameter must be a single value.");
        }

        return $value;
    }

    public function required(string $name): string
    {
        return $this->string($name) ?? throw OAuthException::invalidRequest("The {$name} parameter is required.");
    }
}
