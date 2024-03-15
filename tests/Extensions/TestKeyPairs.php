<?php

namespace Shrd\Laravel\JwtTokens\Tests\Extensions;

use Shrd\Laravel\JwtTokens\Keys\Sets\ArrayKeySet;
use Shrd\Laravel\JwtTokens\Keys\SimpleKey;

abstract class TestKeyPairs
{
    public static function rsaKeyPairs()
    {
        static $rsa_key_pairs;
        if(!isset($rsa_key_pairs)) {
            $rsa_key_pairs = require __DIR__.'/../fixtures/rsa_key_pairs.php';
        }
        return $rsa_key_pairs;
    }

    public static function simplePublicRsaKey(int $ix): SimpleKey
    {
        $keys = self::rsaKeyPairs();
        return SimpleKey::rsa($keys[$ix]['public_key']['pem']);
    }

    public static function simplePublicRsaKeySet(int ...$ixs): ArrayKeySet
    {
        return new ArrayKeySet(array_map(self::simplePublicRsaKey(...), $ixs));
    }
}
