<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use Shrd\Laravel\JwtTokens\Contracts\KeySetLoader;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

abstract class PrefixKeySetLoader implements KeySetLoader
{
    public function __construct(public readonly string $prefix)
    {
    }

    protected function fullDescriptorPrefix(): string
    {
        return $this->prefix.':';
    }

    protected function removeDescriptorPrefix(string $descriptor): string
    {
        $d = str($descriptor);
        $fullPrefix = $this->fullDescriptorPrefix();

        if($d->startsWith($fullPrefix)) {
            return $d->after($fullPrefix)->value();
        } else {
            return $descriptor;
        }
    }

    public abstract function loadKeySet(string $descriptor, array $config): KeySet;
}
