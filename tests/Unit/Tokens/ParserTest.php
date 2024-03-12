<?php

namespace Shrd\Laravel\JwtTokens\Tests\Unit\Tokens;

use Lcobucci\JWT\Encoding\JoseEncoder;
use PHPUnit\Framework\TestCase;
use Shrd\Laravel\JwtTokens\Tokens\Parser;
use SodiumException;

class ParserTest extends TestCase
{
    public function test_parses_none_alg_tokens()
    {
        $jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.";

        $parser = new Parser(decoder: new JoseEncoder);

        $token = $parser->parse($jwt);

        $this->assertEquals([
            "alg" => "none",
            "typ" => "JWT"
        ], $token->headers()->all());

        $this->assertEquals([
            "sub" => "test"
        ], $token->claims()->all());

        $this->assertEquals("", $token->signature()->toString());
        $this->assertEquals("", $token->signature()->hash());
    }

    /**
     * @throws SodiumException
     */
    public function test_parses_rsa_tokens()
    {
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.VdoayMcieBo6d9j_YmNmG6n5QohP1cAOfPbc6BU5s2PdfowNQGfG6uj5cw8sLULKbNEybMEMyecIOqGbcTJaHlyoMsO523LgcQ09Kh2_hCgR1CKFbHaPw0XHJhTOmTzOGOBrP2DVYfqGqwRvUw5Oa_7CrrCA3JgNZ-srnYw_QKx7MGrn3YzDcmSMnidSUZDZ2GZAOr2Mffi9PqK9OTFPE1whMC4gqnT3WDW87Vm2BbtynaXU_nw6JG9K_fns79gL47ptgVsw2Sp7uaB-phB1vPp9PPPpMGZeZF_pZSpLV62mHEpaOvoRiCG6jaKQLAllcGjXr-mRKpwDis9nTJaB0g";
        $signature = 'VdoayMcieBo6d9j_YmNmG6n5QohP1cAOfPbc6BU5s2PdfowNQGfG6uj5cw8sLULKbNEybMEMyecIOqGbcTJaHlyoMsO523LgcQ09Kh2_hCgR1CKFbHaPw0XHJhTOmTzOGOBrP2DVYfqGqwRvUw5Oa_7CrrCA3JgNZ-srnYw_QKx7MGrn3YzDcmSMnidSUZDZ2GZAOr2Mffi9PqK9OTFPE1whMC4gqnT3WDW87Vm2BbtynaXU_nw6JG9K_fns79gL47ptgVsw2Sp7uaB-phB1vPp9PPPpMGZeZF_pZSpLV62mHEpaOvoRiCG6jaKQLAllcGjXr-mRKpwDis9nTJaB0g';

        $parser = new Parser(decoder: new JoseEncoder);

        $token = $parser->parse($jwt);

        $this->assertEquals([
            "alg" => "RS256",
            "typ" => "JWT"
        ], $token->headers()->all());

        $this->assertEquals([
            "sub" => "test"
        ], $token->claims()->all());

        $this->assertEquals(
            $signature,
            $token->signature()->toString()
        );

        $this->assertEquals(
            sodium_base642bin($signature, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
            $token->signature()->hash()
        );
    }
}
