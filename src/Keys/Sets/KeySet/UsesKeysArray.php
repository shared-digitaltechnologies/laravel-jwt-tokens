<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

use Iterator;
use ArrayIterator;
use LogicException;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;

trait UsesKeysArray
{
    public function has(string|int $keyIdOrIx): bool
    {
        if(is_string($keyIdOrIx)) {
            return $this->getKeyById($keyIdOrIx) !== null;
        } else {
            return count($this->keys) > $keyIdOrIx;
        }
    }

    public function get(string|int $keyIdOrIx): ?VerificationKey
    {
        if(is_string($keyIdOrIx)) {
            return $this->getKeyById($keyIdOrIx);
        } else {
            return $this->keys[$keyIdOrIx] ?? null;
        }
    }

    public function all(): array
    {
        return $this->keys;
    }

    public function offsetExists(mixed $offset): bool
    {
        return $this->has($offset);
    }

    public function offsetGet(mixed $offset): ?VerificationKey
    {
        return $this->get($offset);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        throw new LogicException(static::class." is immutable");
    }

    public function offsetUnset(mixed $offset): void
    {
        throw new LogicException(static::class." is immutable");
    }

    public function getIterator(): Iterator
    {
        return new ArrayIterator($this->keys);
    }

    public function count(): int
    {
        return count($this->keys);
    }
}
