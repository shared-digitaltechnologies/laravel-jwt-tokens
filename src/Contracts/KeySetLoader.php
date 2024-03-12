<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

interface KeySetLoader
{
    /**
     * @param string $descriptor
     * @param array $config
     * @return KeySet
     */
    public function loadKeySet(string $descriptor, array $config): KeySet;
}
