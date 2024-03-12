<?php

namespace Shrd\Laravel\JwtTokens\Signers;

interface Verifier
{
    public function verify(string $expected, string $payload): bool;
}
