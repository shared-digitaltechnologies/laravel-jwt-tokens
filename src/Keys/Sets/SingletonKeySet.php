<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets;

use ArrayAccess;
use Generator;
use LogicException;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;

/**
 * @template T of VerificationKey
 * @implements PointedKeySet<T>
 * @implements ArrayAccess<string|0, VerificationKey&T>
 */
readonly class SingletonKeySet implements PointedKeySet, ArrayAccess, VerificationKey
{
    /**
     * @param VerificationKey&T $key
     */
    public function __construct(public VerificationKey $key)
    {
    }

    public function getKey(): VerificationKey
    {
        return $this->key;
    }

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

    public function contents(): string
    {
        return $this->getKey()->contents();
    }

    public function passphrase(): string
    {
        return $this->getKey()->passphrase();
    }

    public function supportedByAlgorithm(Algorithm $algorithm): bool
    {
        return $this->getKey()->supportedByAlgorithm($algorithm);
    }
}
