<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Lcobucci\JWT\Token\DataSet;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

interface IssuesTokens
{
    /**
     * Should return `true` if this issuer matches the issuer claim of a token.
     *
     * @param DataSet $claims
     * @return bool
     */
    public function couldHaveIssuedTokenClaims(DataSet $claims): bool;

    /**
     * Should give a key set descriptor.
     *
     * @return KeySet|string|string[]
     */
    public function jwtVerificationKeySet(): KeySet|string|array;
}
