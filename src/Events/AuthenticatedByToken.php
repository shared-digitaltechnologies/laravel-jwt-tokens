<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Token;
use Shrd\Laravel\JwtTokens\Contracts\TokenUserProvider;

readonly class AuthenticatedByToken implements Authenticated
{
    use DerivesClaimsFromToken;

    public function __construct(public string $guard,
                                public Authenticatable $user,
                                public Token $token)
    {
    }

    public function guardName(): string
    {
        return $this->guard;
    }

    public function token(): Token
    {
        return $this->token;
    }

    public function user(): Authenticatable
    {
        return $this->user;
    }
}
