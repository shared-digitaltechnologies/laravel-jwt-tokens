<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

readonly class AuthenticatedByClaims implements Authenticated
{
    public function __construct(public string          $guard,
                                public Authenticatable $user,
                                public ClaimsBag       $claims)
    {
    }

    public function claims(): ClaimsBag
    {
        return $this->claims;
    }

    public function user(): Authenticatable
    {
        return $this->user;
    }

    public function guardName(): string
    {
        return $this->guard;
    }
}
