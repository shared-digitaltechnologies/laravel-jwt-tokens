<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets;

use Shrd\Laravel\JwtTokens\Keys\NoneKey;

/**
 * @extends SingletonKeySet<NoneKey>
 */
readonly class NoneKeySet extends SingletonKeySet
{
    public function __construct(?string $kid = null)
    {
        return parent::__construct(new NoneKey($kid));
    }
}
