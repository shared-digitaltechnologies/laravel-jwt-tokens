<?php

namespace Shrd\Laravel\JwtTokens\Tests\Unit\Keys;

use Safe\Exceptions\JsonException;
use Shrd\EncodingCombinators\Exceptions\WrappedDecodeException;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwkPropertyException;
use Shrd\Laravel\JwtTokens\Keys\JWK;
use Shrd\Laravel\JwtTokens\Tests\Extensions\TestKeyPairs;
use Shrd\Laravel\JwtTokens\Tests\TestCase;

class JWKTest extends TestCase
{
    public static function jwk_public_keys(): array
    {
        return array_map(fn($x) => [
            $x['public_key']['jwk'],
            $x['public_key']['pem']
        ], TestKeyPairs::rsaKeyPairs());
    }

    /**
     * @dataProvider jwk_public_keys
     * @param $jwk
     * @param $pem
     * @return void
     * @throws JsonException
     * @throws WrappedDecodeException
     * @throws InvalidJwkPropertyException
     */
    public function test_converts_jwk_to_public_key($jwk, $pem)
    {
        $key = openssl_pkey_get_public(JWK::from($jwk)->contents());

        $this->assertEquals($pem, openssl_pkey_get_details($key)['key']);
    }
}
