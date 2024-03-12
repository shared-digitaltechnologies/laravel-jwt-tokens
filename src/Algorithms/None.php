<?php

namespace Shrd\Laravel\JwtTokens\Algorithms;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key;
use Shrd\Laravel\JwtTokens\Keys\NoneKey;
use Shrd\Laravel\JwtTokens\Signers\Signer;
use Shrd\Laravel\JwtTokens\Signers\Verifier;

class None implements \Lcobucci\JWT\Signer, Signer, Verifier
{

    public function algorithmId(): string
    {
        return 'none';
    }

    private function assertNullOrNoneKey(?Key $key): void
    {
        if($key && !($key instanceof NoneKey)) {
            throw new InvalidKeyProvided("Key must be an instance of ".NoneKey::class." if provided.");
        }
    }

    public function sign(string $payload = '', ?Key $key = null): string
    {
        $this->assertNullOrNoneKey($key);
        return '';
    }

    public function verify(string $expected, string $payload = '', ?Key $key = null): bool
    {
        $this->assertNullOrNoneKey($key);
        return $expected === '';
    }
}
