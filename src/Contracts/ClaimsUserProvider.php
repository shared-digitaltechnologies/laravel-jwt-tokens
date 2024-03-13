<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Token;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

/**
 * Retrieves authenticatables from jwt token claims.
 */
interface ClaimsUserProvider
{

    /**
     * Retrieves a user using the provided JWT token. It is expected that this method also validates the token.
     *
     * @param Token $token
     * @return Authenticatable|null
     */
    public function retrieveByJwtToken(Token $token): ?Authenticatable;

    /**
     * Retrieves a user using the provided claims.
     *
     * @param ClaimsBag $claims
     * @return Authenticatable|null
     */
    public function retrieveByClaims(ClaimsBag $claims): ?Authenticatable;
}
