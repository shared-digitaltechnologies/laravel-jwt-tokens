<?php

namespace Shrd\Laravel\JwtTokens\Keys;

use Lcobucci\JWT\Signer\Key as BaseKey;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;

interface VerificationKey extends BaseKey
{
    public function getKeyId(): ?string;

    public function supportedByAlgorithm(Algorithm $algorithm): bool;
}
