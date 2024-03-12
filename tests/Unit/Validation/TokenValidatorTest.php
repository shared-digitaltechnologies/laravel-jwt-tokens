<?php

namespace Shrd\Laravel\JwtTokens\Tests\Unit\Validation;

use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Signature;
use Shrd\Laravel\JwtTokens\Tests\TestCase;
use Shrd\Laravel\JwtTokens\Tokens\Token;
use Shrd\Laravel\JwtTokens\Validation\TokenValidator;

class TokenValidatorTest extends TestCase
{
    public function test_calls_constraint_assertions()
    {
        $token = new Token(
            new DataSet([], 'AAAA'),
            new DataSet([], 'BBBB'),
            new Signature('','')
        );

        $validator = new TokenValidator($token, );
    }
}
