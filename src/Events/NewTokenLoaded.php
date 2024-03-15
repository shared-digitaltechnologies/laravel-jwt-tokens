<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Lcobucci\JWT\UnencryptedToken;

readonly class NewTokenLoaded
{
    public function __construct(protected UnencryptedToken $token)
    {
    }
}
