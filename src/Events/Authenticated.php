<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Illuminate\Contracts\Auth\Authenticatable;

interface Authenticated extends JwtGuardEvent
{
    public function user(): Authenticatable;
}
