<?php

namespace Shrd\Laravel\JwtTokens\Signers;

use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

readonly class KeySetVerifier implements Verifier
{
    protected array $keys;

    public function __construct(public Algorithm $algorithm, KeySet $keySet)
    {
        $this->keys = iterator_to_array($keySet->forAlgorithm($this->algorithm), false);
    }

    public function count(): int
    {
        return count($this->keys);
    }

    public function verify(string $expected, string $payload): bool
    {
        foreach ($this->keys as $key) {
            if($this->algorithm->verify($expected, $payload, $key)) return true;
        }
        return false;
    }
}
