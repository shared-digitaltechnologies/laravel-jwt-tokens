<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use phpseclib3\Crypt\PublicKeyLoader;
use Shrd\Laravel\JwtTokens\Contracts\KeySetLoader;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Keys\Sets\SingletonKeySet;
use Shrd\Laravel\JwtTokens\Keys\WrappedAsymmetricKey;

class AsymmetricKeyLoader implements KeySetLoader
{

    public function loadKeySet(string $descriptor, array $config): KeySet
    {
        $password = $config['password'] ?? false;
        $kid = $config['kid'] ?? null;

        $key = PublicKeyLoader::load($descriptor, password: $password);

        return new SingletonKeySet(new WrappedAsymmetricKey($key, $kid));
    }
}
