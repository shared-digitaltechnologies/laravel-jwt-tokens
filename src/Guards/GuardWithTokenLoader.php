<?php

namespace Shrd\Laravel\JwtTokens\Guards;

use Shrd\Laravel\JwtTokens\Contracts\TokenLoader;

interface GuardWithTokenLoader
{
    public function getTokenLoader(): TokenLoader;

    public function setTokenLoader(TokenLoader $loader): static;
}
