<?php

namespace Shrd\Laravel\JwtTokens\Keys;

use Lcobucci\JWT\Signer\Key as BaseKey;

interface SigningKey extends BaseKey
{
    public function getKeyId(): ?string;
}
