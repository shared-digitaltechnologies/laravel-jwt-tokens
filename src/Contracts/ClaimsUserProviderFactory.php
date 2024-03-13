<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

/**
 * Constructs token user provider factories.
 */
interface ClaimsUserProviderFactory
{
    public function createClaimsUserProvider(?string $provider = null): ClaimsUserProvider;
}
