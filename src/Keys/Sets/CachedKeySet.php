<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets;

use Shrd\Laravel\JwtTokens\Keys\CachedVerificationKey;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;

readonly class CachedKeySet implements KeySet
{
    use KeySet\UsesFilterForAlgorithm,
        KeySet\UsesKeysArray,
        KeySet\UsesIteratorForKeyIds;

    /**
     * @var array<string, CachedVerificationKey>
     */
    protected array $keys;

    public function __construct(KeySet $keySet)
    {
        $keys = [];

        foreach ($keySet as $key) {
            $keys[] = new CachedVerificationKey($key);
        }

        $this->keys = $keys;
    }

    public function getKeyById(string $kid): ?VerificationKey
    {
        foreach ($this->keys as $key) {
            if($key->getKeyId() === $kid) return $key;
        }
        return null;
    }
}
