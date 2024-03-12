<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets;

use ArrayAccess;
use Countable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use InvalidArgumentException;
use JsonSerializable;
use Safe\Exceptions\JsonException;
use Shrd\Laravel\JwtTokens\Keys\JWK;

/**
 * @implements KeySet<JWK>
 * @implements ArrayAccess<string|int, JWK>
 * @implements Arrayable<int, JWK>
 */
readonly class JWKSet implements ArrayAccess, Arrayable, Jsonable, JsonSerializable, Countable, KeySet
{
    use KeySet\UsesKeysArray,
        KeySet\UsesFilterForAlgorithm;

    /**
     * @var array<string, JWK>
     */
    protected array $keysByKid;

    /**
     * @param JWK[] $keys
     */
    protected function __construct(protected array $keys = [])
    {
        $keysByKid = [];

        foreach ($this->keys as $key) {
            assert($key instanceof JWK);
            $kid = $key->getKeyId();
            if($kid !== null) {
                $keysByKid[$kid] = $key;
            }
        }

        $this->keysByKid = $keysByKid;
    }

    public function keyIds(): array
    {
        return array_values($this->keysByKid);
    }

    /**
     * @throws JsonException
     */
    public static function fromJson(string $value): static
    {
        $value = \Safe\json_decode($value, assoc: true);
        return static::fromArray($value);
    }

    /**
     * @throws JsonException
     */
    public static function fromJWKs(iterable $jwks): static
    {
        $keys = [];
        foreach ($jwks as $jwk) {
            $keys[] = JWK::from($jwk);
        }
        return new static($keys);
    }

    /**
     * @throws JsonException
     */
    public static function fromArray(array $value): static
    {
        if(array_key_exists('keys', $value)) {
            $value = $value['keys'];
        }

        if(array_is_list($value)) {
            return static::fromJWKs($value);
        }

        throw new InvalidArgumentException("Invalid jwks array.");
    }

    /**
     * @throws JsonException
     */
    public static function from(string|JWKSet|JWK|iterable|null $value): JWKSet
    {
        if($value instanceof static) return $value;
        /** @noinspection PhpConditionAlreadyCheckedInspection */
        if($value instanceof self) return new static($value->all());
        if($value instanceof JWK) return new static([$value]);
        if($value === null) return static::empty();
        if(is_string($value)) return static::fromJson($value);
        if(is_array($value)) return static::fromArray($value);
        if(is_iterable($value)) return static::fromJWKs($value);

        throw new InvalidArgumentException(
            "Could not convert a '".get_debug_type($value)."' to a ".static::class
        );
    }

    public static function empty(): static
    {
        return new static([]);
    }

    public function toArray(): array
    {
        return array_map(fn(JWK $jwk) => $jwk->toArray(), $this->keys);
    }

    public function toString(): string
    {
        return $this->toJson(JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function toJson($options = 0): string
    {
        return json_encode($this->jsonSerialize(), $options);
    }

    public function jsonSerialize(): array
    {
        return [ "keys" => $this->keys ];
    }

    public function getKeyById(string $kid): ?JWK
    {
        return $this->keysByKid[$kid] ?? null;
    }

}
