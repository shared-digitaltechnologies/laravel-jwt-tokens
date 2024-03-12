<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets;

use Countable;
use IteratorAggregate;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;
use Traversable;

/**
 * @template T of VerificationKey
 * @extends IteratorAggregate<int, VerificationKey&T>
 */
interface KeySet extends IteratorAggregate, Countable
{
    /**
     * @param string $kid
     * @return (VerificationKey&T)|null
     */
    public function getKeyById(string $kid): ?VerificationKey;

    /**
     * @return iterable<int, string>
     */
    public function keyIds(): iterable;

    /**
     * @param Algorithm $algorithm
     * @return Traversable<array-key, VerificationKey&T>
     */
    public function forAlgorithm(Algorithm $algorithm): Traversable;

}
