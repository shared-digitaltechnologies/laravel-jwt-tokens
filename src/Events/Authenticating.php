<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

interface Authenticating extends JwtGuardEvent
{
    public function claims(): ClaimsBag;
}
