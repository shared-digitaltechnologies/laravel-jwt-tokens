<?php

namespace Shrd\Laravel\JwtTokens\Signers;

use Lcobucci\JWT\Signer\Key;

readonly class WrappedVerifier implements Verifier
{
    public function __construct(public \Lcobucci\JWT\Signer $algorithm,
                                public Key $publicKey)
    {
    }

    public function verify(string $expected, string $payload): bool
    {
        return $this->algorithm->verify($expected, $payload, $this->publicKey);
    }
}
