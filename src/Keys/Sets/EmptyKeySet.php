<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets;

use EmptyIterator;
use Iterator;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;

readonly class EmptyKeySet implements KeySet
{

    public function getKeyById(string $kid): ?VerificationKey
    {
        return null;
    }

    public function forAlgorithm(Algorithm $algorithm): Iterator
    {
        return new EmptyIterator;
    }

    public function getIterator(): Iterator
    {
        return new EmptyIterator;
    }

    public function count(): int
    {
        return 0;
    }

    public function keyIds(): iterable
    {
        return [];
    }
}
