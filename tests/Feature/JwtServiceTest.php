<?php

namespace Shrd\Laravel\JwtTokens\Tests\Feature;

use Shrd\Laravel\JwtTokens\Exceptions\KeySetLoadException;
use Shrd\Laravel\JwtTokens\Facades\JWT;
use Shrd\Laravel\JwtTokens\Tests\TestCase;

class JwtServiceTest extends TestCase
{
    /**
     * @throws KeySetLoadException
     */
    public function test_loads_jwks_uri()
    {
        $keySet = JWT::keys('https://precontoolsstaging.b2clogin.com/precontoolsstaging.onmicrosoft.com/b2c_1a_signup_signin/.well-known/openid-configuration');



        dd((string)$keySet);
    }
}
