<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;
use Traversable;
use Generator;

trait UsesFilterForAlgorithm
{
    /**
     * @return Traversable<int, VerificationKey>
     */
    public abstract function getIterator(): Traversable;

    public function forAlgorithm(Algorithm $algorithm): Generator
    {
        foreach ($this->getIterator() as $key) {
            if($key->supportedByAlgorithm($algorithm)) {
                yield $key;
            }
        }
    }
}
