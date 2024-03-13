<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

trait RemovesDescriptorPrefixes
{
    protected abstract function getDescriptorPrefix(): string;

    protected function fullDescriptorPrefix(): string
    {
        return $this->getDescriptorPrefix().':';
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
}
