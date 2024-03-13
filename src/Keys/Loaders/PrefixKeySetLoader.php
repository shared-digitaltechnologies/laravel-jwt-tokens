<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use Shrd\Laravel\JwtTokens\Contracts\KeySetLoader;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

abstract class PrefixKeySetLoader implements KeySetLoader
{
    use RemovesDescriptorPrefixes;

    public function __construct(public readonly string $prefix)
    {
    }

    protected function getDescriptorPrefix(): string
    {
        return $this->prefix;
    }

    public abstract function loadKeySet(string $descriptor, array $config): KeySet;
}
