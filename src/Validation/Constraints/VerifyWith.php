<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\SignedWith as SignedWithInterface;
use Shrd\Laravel\JwtTokens\Signers\Verifier;

readonly class VerifyWith implements SignedWithInterface
{
    public function __construct(public Verifier $verifier)
    {
    }

    public function assert(Token $token): void
    {
        if(! $token instanceof UnencryptedToken) {
            throw new ConstraintViolation("You should pass an unencrypted token.", static::class);
        }

        $valid = $this->verifier->verify(
            expected: $token->signature()->hash(),
            payload: $token->payload()
        );

        if(!$valid) {
            throw new ConstraintViolation(
                message: "Failed to very token signature.",
                constraint: static::class
            );
        }

    }
}
