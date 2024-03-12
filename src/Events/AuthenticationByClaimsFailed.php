<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;
use Throwable;

readonly class AuthenticationByClaimsFailed implements AuthenticationFailed
{
    public function __construct(public string $guard,
                                public ClaimsBag $claims,
                                public ?Throwable $exception = null)
    {
    }

    public function claims(): ClaimsBag
    {
        return $this->claims;
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
