<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

readonly class AuthenticatingByClaims implements Authenticating
{
    public function __construct(public string            $guard,
                                public ClaimsBag         $claims)
    {
    }

    public function claims(): ClaimsBag
    {
        return $this->claims;
    }

    public function guardName(): string
    {
        return $this->guard;
    }
}
