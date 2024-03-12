<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use Illuminate\Support\Str;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Keys\Sets\NoneKeySet;

class NoneLoader extends PrefixKeySetLoader
{
    public function __construct(string $prefix)
    {
        parent::__construct($prefix);
    }

    public function loadKeySet(string $descriptor, array $config): KeySet
    {
        if(array_key_exists('kid', $config)) {
            $kid = $config['kid'];
        } else if(Str::lower($descriptor) === 'none') {
            $kid = '';
        } else {
            $kid = $this->removeDescriptorPrefix($descriptor);
        }

        if(strlen($kid) > 0) {
            return new NoneKeySet($kid);
        } else {
            return new NoneKeySet();
        }
    }
}
