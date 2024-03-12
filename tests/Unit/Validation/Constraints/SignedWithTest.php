<?php

namespace Shrd\Laravel\JwtTokens\Tests\Unit\Validation\Constraints;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\TestCase;
use Shrd\Laravel\JwtTokens\Tests\Extensions\TestKeyPairs;
use Shrd\Laravel\JwtTokens\Tokens\Parser;
use Shrd\Laravel\JwtTokens\Tokens\Token;
use Shrd\Laravel\JwtTokens\Validation\Constraints\SignedWith;

class SignedWithTest extends TestCase
{
    protected function tokenA(): Token
    {
        static $token;

        if(!isset($token)) {
            $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.VdoayMcieBo6d9j_YmNmG6n5QohP1cAOfPbc6BU5s2PdfowNQGfG6uj5cw8sLULKbNEybMEMyecIOqGbcTJaHlyoMsO523LgcQ09Kh2_hCgR1CKFbHaPw0XHJhTOmTzOGOBrP2DVYfqGqwRvUw5Oa_7CrrCA3JgNZ-srnYw_QKx7MGrn3YzDcmSMnidSUZDZ2GZAOr2Mffi9PqK9OTFPE1whMC4gqnT3WDW87Vm2BbtynaXU_nw6JG9K_fns79gL47ptgVsw2Sp7uaB-phB1vPp9PPPpMGZeZF_pZSpLV62mHEpaOvoRiCG6jaKQLAllcGjXr-mRKpwDis9nTJaB0g";
            $parser = new Parser(decoder: new JoseEncoder);
            $token = $parser->parse($jwt);
        }

        return $token;
    }

    public function test_signed_with_single_rsa_key_succeeds()
    {
        $constraint = new SignedWith(TestKeyPairs::simplePublicRsaKeySet(0));

        $constraint->assert($this->tokenA());

        $this->expectNotToPerformAssertions();
    }

    public function test_signed_with_other_single_rsa_key_fails()
    {
        $constraint = new SignedWith(TestKeyPairs::simplePublicRsaKeySet(1));

        $this->expectException(ConstraintViolation::class);

        $constraint->assert($this->tokenA());
    }

    public function test_signed_with_multiple_rsa_keys_succeeds()
    {
        $constraint = new SignedWith(TestKeyPairs::simplePublicRsaKeySet(1,2,0));

        $constraint->assert($this->tokenA());

        $this->expectNotToPerformAssertions();
    }

    public function test_signed_with_multiple_rsa_keys_fails()
    {
        $constraint = new SignedWith(TestKeyPairs::simplePublicRsaKeySet(1,2,3));

        $this->expectException(ConstraintViolation::class);

        $constraint->assert($this->tokenA());
    }
}
