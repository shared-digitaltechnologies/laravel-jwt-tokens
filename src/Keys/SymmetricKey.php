<?php

namespace Shrd\Laravel\JwtTokens\Keys;

interface SymmetricKey extends VerificationKey, SigningKey
{
    public function getKeyBitsLength(): int;
}
