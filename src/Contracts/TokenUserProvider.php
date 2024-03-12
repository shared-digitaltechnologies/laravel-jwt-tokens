<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Token;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

/**
 * Retrieves authenticatables from jwt token claims.
 */
interface TokenUserProvider
{
    /**
     * Retrieves a user using a token. This method should also check whether the token is valid.
     *
     * @param Token $token
     * @return Authenticatable|null
     */
    public function retrieveByToken(Token $token): ?Authenticatable;

    /**
     * Retrieves a user using the provided claims.
     *
     * @param ClaimsBag $claims
     * @return Authenticatable|null
     */
    public function retrieveByClaims(ClaimsBag $claims): ?Authenticatable;
}
