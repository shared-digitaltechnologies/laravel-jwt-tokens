<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

/**
 * Constructs token user provider factories.
 */
interface TokenUserProviderFactory
{
    public function createTokenUserProvider(?string $provider = null): TokenUserProvider;
}
