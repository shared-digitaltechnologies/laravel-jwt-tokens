<?php

namespace Shrd\Laravel\JwtTokens\Tokens\Headers;

use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;

class HeadersBag
{
    public function __construct(protected array $headers)
    {
    }

    public function getAlgorithm(): Algorithm
    {
        return Algorithm::fromAlgorithmId($this->headers['alg']);
    }
}
