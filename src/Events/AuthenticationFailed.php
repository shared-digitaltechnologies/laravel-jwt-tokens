<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Throwable;

interface AuthenticationFailed extends JwtGuardEvent
{
    public function exception(): ?Throwable;
}
