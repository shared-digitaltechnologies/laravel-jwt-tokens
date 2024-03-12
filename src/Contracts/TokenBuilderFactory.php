<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Shrd\Laravel\JwtTokens\Tokens\Builder;

interface TokenBuilderFactory
{
    public function builder(?string $builder = null): Builder;
}
