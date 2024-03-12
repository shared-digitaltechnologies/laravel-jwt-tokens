<?php

namespace Shrd\Laravel\JwtTokens\Events;

interface JwtGuardEvent
{
    public function guardName(): string;
}
