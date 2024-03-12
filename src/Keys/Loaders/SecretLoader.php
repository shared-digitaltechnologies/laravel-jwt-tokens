<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use Exceptions\DecodeException;
use Shrd\EncodingCombinators\Strings\Decoder;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Keys\Sets\SingletonKeySet;
use Shrd\Laravel\JwtTokens\Keys\StringSymmetricKey;

class SecretLoader extends PrefixKeySetLoader
{
    public function __construct(protected Decoder $decoder, string $prefix)
    {
        parent::__construct($prefix);
    }

    /**
     * @throws DecodeException
     */
    public function loadKeySet(string $descriptor, array $config): KeySet
    {
        $encoded = $this->removeDescriptorPrefix($descriptor);
        $contents = $this->decoder->decode($encoded);
        $kid = $config['kid'] ?? null;

        $key = new StringSymmetricKey($contents, $kid);

        return new SingletonKeySet($key);
    }
}
