<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

/**
 * Retrieves authenticatables from jwt token claims.
 */
interface ClaimsUserProvider
{
    /**
     * Retrieves a user using the provided claims.
     *
     * @param ClaimsBag $claims
     * @return Authenticatable|null
     */
    public function retrieveByClaims(ClaimsBag $claims): ?Authenticatable;
}
