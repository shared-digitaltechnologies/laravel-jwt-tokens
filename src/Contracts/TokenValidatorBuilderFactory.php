<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Shrd\Laravel\JwtTokens\Validation\Builder;

interface TokenValidatorBuilderFactory
{
    public function createValidatorBuilder(): Builder;
}
