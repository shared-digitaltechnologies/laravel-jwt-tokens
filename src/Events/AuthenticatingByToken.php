<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Lcobucci\JWT\Token;

readonly class AuthenticatingByToken implements Authenticating
{
    use DerivesClaimsFromToken;

    public function __construct(public string $guard,
                                public Token $token)
    {
    }

    public function token(): Token
    {
        return $this->token;
    }

    public function guardName(): string
    {
        return $this->guard;
    }
}
