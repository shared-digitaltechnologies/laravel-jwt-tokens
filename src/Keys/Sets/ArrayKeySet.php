<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets;

use ArrayAccess;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;

/**
 * @template T of VerificationKey
 * @implements KeySet<T>
 * @implements ArrayAccess<string|int, T&VerificationKey>
 */
readonly class ArrayKeySet implements KeySet, ArrayAccess
{
    use KeySet\UsesFilterForAlgorithm,
        KeySet\UsesKeysArray;

    /**
     * @var array<string, VerificationKey&T>
     */
    protected array $keysByKeyId;

    /**
     * @param (VerificationKey&T)[] $keys
     */
    public function __construct(public array $keys)
    {
        $keysByKeyId = [];

        foreach ($keys as $key) {
            assert($key instanceof VerificationKey);
            $kid = $key->getKeyId();
            if($kid !== null) {
                $keysByKeyId[$kid] = $key;
            }
        }

        $this->keysByKeyId = $keysByKeyId;
    }

    public static function empty(): static
    {
        return new static([]);
    }

    public function keyIds(): array
    {
        return array_keys($this->keysByKeyId);
    }

    public function getKeyById(string $kid): ?VerificationKey
    {
        return $this->keysByKeyId[$kid] ?? null;
    }
}
