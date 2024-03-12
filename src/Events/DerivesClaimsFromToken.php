<?php

namespace Shrd\Laravel\JwtTokens\Events;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

trait DerivesClaimsFromToken
{
    public abstract function token(): Token;

    public function claims(): ClaimsBag
    {
        $token = $this->token();
        if($token instanceof \Shrd\Laravel\JwtTokens\Tokens\Token) {
            return $token->claims;
        } else if($token instanceof UnencryptedToken) {
            return ClaimsBag::fromDataSet($token->claims());
        } else {
            return ClaimsBag::empty();
        }
    }
}
