<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\SignedWith as SignedWithInterface;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Exceptions\UnsupportedAlgorithmException;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

readonly class SignedWith implements SignedWithInterface
{
    public function __construct(protected KeySet $keySet)
    {
    }

    public function assert(Token $token): void
    {
        $alg = $token->headers()->get('alg');
        if($alg === null) {
            throw new ConstraintViolation("Token has no `alg` header.", static::class);
        }

        try {
            $algorithm = Algorithm::fromAlgorithmId($alg);
        } catch (UnsupportedAlgorithmException) {
            throw new ConstraintViolation("Algorithm '$alg' not supported.", static::class);
        }

        if(! $token instanceof UnencryptedToken) {
            throw new ConstraintViolation("You should pass an unencrypted token.", static::class);
        }

        $kid = $token->headers()->get('kid');
        if($kid !== null) {
            $key = $this->keySet->getKeyById($kid);
            if(!$key) {
                throw new ConstraintViolation("Could not find key with kid='$kid'.", static::class);
            }

            if(!$algorithm->verify($token->signature()->hash(), $token->payload(), $key)) {
                throw new ConstraintViolation("Token signature mismatch", static::class);
            }
        } else {
            $keys = 0;
            foreach ($this->keySet->forAlgorithm($algorithm) as $key) {
                $keys++;
                if($algorithm->verify($token->signature()->hash(), $token->payload(), $key)) {
                    return;
                }
            }

            if($keys === 0) {
                throw new ConstraintViolation(
                    message: "KeySet contains no keys for algorithm '$alg'.",
                    constraint: static::class
                );
            } else {
                throw new ConstraintViolation(
                    message: "Token signature mismatch for all '$keys' keys supporting the '$alg' algorithm.",
                    constraint: static::class
                );
            }
        }
    }
}
