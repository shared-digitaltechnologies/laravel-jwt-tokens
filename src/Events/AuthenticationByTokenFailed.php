<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Lcobucci\JWT\Token;
use Throwable;

readonly class AuthenticationByTokenFailed implements AuthenticationFailed
{
    use DerivesClaimsFromToken;

    public function __construct(public string $guard,
                                public Token $token,
                                public ?Throwable $exception = null)
    {
    }

    public function token(): Token
    {
        return $this->token;
    }

    public function exception(): ?Throwable
    {
        return $this->exception;
    }

    public function guardName(): string
    {
        return $this->guard;
    }
}
