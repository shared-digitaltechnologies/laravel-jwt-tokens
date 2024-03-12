<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Lcobucci\JWT\Parser;
use Throwable;

readonly class JwtFailedToParse implements JwtGuardEvent
{
    public function __construct(public string $guard,
                                public Parser $parser,
                                public string $jwt,
                                public ?Throwable $exception)
    {
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
