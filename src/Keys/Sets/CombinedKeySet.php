<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets;

use Generator;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;

/**
 * @template T of VerificationKey
 * @implements KeySet<T>
 */
readonly class CombinedKeySet implements KeySet
{
    protected array $keySets;

    /**
     * @param KeySet<T> ...$keySets
     */
    public function __construct(KeySet ...$keySets)
    {
        $this->keySets = $keySets;
    }

    public function getIterator(): Generator
    {
        foreach ($this->keySets as $keySet) {
            yield from $keySet->getIterator();
        }
    }

    /**
     * @param string $kid
     * @return (VerificationKey&T)|null
     */
    public function getKeyById(string $kid): ?VerificationKey
    {
        foreach ($this->keySets as $keySet) {
            $result = $keySet->getKeyById($kid);
            if($result !== null) return $result;
        }
        return null;
    }

    public function forAlgorithm(Algorithm $algorithm): Generator
    {
        foreach ($this->keySets as $keySet) {
            yield from $keySet->forAlgorithm($algorithm);
        }
    }

    public function keyIds(): iterable
    {
        foreach ($this->keySets as $keySet) {
            yield from $keySet->keyIds();
        }
    }

    public function count(): int
    {
        $result = 0;
        foreach ($this->keySets as $keySet) {
            $result += $keySet->count();
        }
        return $result;
    }
}
