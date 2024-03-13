<?php

namespace Shrd\Laravel\JwtTokens\Signers;

use Lcobucci\JWT\Signer\Key;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

readonly class WrappedVerifier implements Verifier
{
    public function __construct(public \Lcobucci\JWT\Signer $algorithm,
                                public Key|KeySet $publicKey)
    {
    }

    public function verify(string $expected, string $payload): bool
    {
        if($this->publicKey instanceof Key) {
            return $this->algorithm->verify($expected, $payload, $this->publicKey);
        } else {
            $alg = Algorithm::tryFrom($this->algorithm->algorithmId());

            $keys = $alg === null ? $this->publicKey : $this->publicKey->forAlgorithm($alg);

            foreach ($keys as $key) {
                if($this->algorithm->verify($expected, $payload, $key)) {
                    return true;
                }
            }

            return false;
        }
    }
}
