<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

use Generator;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;

trait UsesSingletonKeySet
{
    abstract public function getKey(): VerificationKey;

    public function keyIds(): array
    {
        $kid = $this->getKeyId();
        if($kid === null) {
            return [];
        } else {
            return [$kid];
        }
    }

    public function get(string|int|null $keyIdOrIx = null): ?VerificationKey
    {
        if(is_string($keyIdOrIx)) {
            return $this->getKeyById($keyIdOrIx);
        } else if($keyIdOrIx === 0) {
            return $this->getKey();
        } else {
            return null;
        }
    }

    public function has(string|int $keyIdOrIx): bool
    {
        return (is_string($keyIdOrIx) && $this->getKeyId() === $keyIdOrIx)
            || $keyIdOrIx === 0;
    }

    public function all(): array
    {
        return [$this->getKey()];
    }

    public function getKeyId(): ?string
    {
        return $this->getKey()->getKeyId();
    }

    public function getKeyById(string $kid): ?VerificationKey
    {
        if($kid === $this->getKeyId()) return $this->getKey();
        else return null;
    }

    public function getIterator(): Generator
    {
        yield $this->getKey();
    }

    public function forAlgorithm(Algorithm $algorithm): Generator
    {
        $key = $this->getKey();
        if ($key->supportedByAlgorithm($algorithm)) {
            yield $key;
        }
    }

    public function count(): int
    {
        return 1;
    }
}
