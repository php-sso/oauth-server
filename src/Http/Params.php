<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Http;

use PhpSso\OAuthServer\Exception\OAuthException;
use Psr\Http\Message\ServerRequestInterface;

/** The parameters of an OAuth request, read as strings. A parameter given as an array is an error. */
final readonly class Params
{
    /** @param array<array-key, mixed> $values */
    private function __construct(private array $values, private string $raw = '')
    {
    }

    public static function fromQuery(ServerRequestInterface $request): self
    {
        return new self($request->getQueryParams(), $request->getUri()->getQuery());
    }

    /** The form body. Uses the parsed body when a framework already decoded it, and decodes the raw form otherwise. */
    public static function fromBody(ServerRequestInterface $request): self
    {
        $raw = (string) $request->getBody();
        $parsed = $request->getParsedBody();
        if (is_array($parsed)) {
            return new self($parsed, $raw);
        }

        $values = [];
        parse_str($raw, $values);

        return new self($values, $raw);
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

    /**
     * Every value of a parameter that may be repeated, such as `resource` (RFC 8707): `a=1&a=2`, which PHP's own parsing
     * would reduce to the last one. A framework that already collected them as an array (`a[]=1&a[]=2`) works too.
     *
     * @return list<string>
     *
     * @throws OAuthException when a value is empty or not a string
     */
    public function repeated(string $name): array
    {
        $found = [];
        foreach ($this->raw === '' ? [] : explode('&', $this->raw) as $pair) {
            [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
            if (urldecode($key) === $name) {
                $found[] = urldecode($value);
            }
        }
        if ($found === []) {
            $value = $this->values[$name] ?? null;
            $found = $value === null ? [] : (is_array($value) ? array_values($value) : [$value]);
        }
        foreach ($found as $item) {
            if (!is_string($item) || $item === '') {
                throw OAuthException::invalidRequest("The {$name} parameter must be made of non-empty strings.");
            }
        }

        /** @var list<string> $found */
        return $found;
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
