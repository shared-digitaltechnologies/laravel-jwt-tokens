<?php

namespace Shrd\Laravel\JwtTokens\Tokens;

use DateTimeInterface;

interface VerifiedToken
{
    public function getValidFrom(): DateTimeInterface;
    public function getValidTill(): DateTimeInterface;
    public function isValidAt(DateTimeInterface $now): bool;
}
