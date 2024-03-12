<?php

namespace Shrd\Laravel\JwtTokens\Signers;

readonly final class NoneSigner implements Signer, Verifier
{
    public function sign(string $payload): string
    {
        return '';
    }

    public function verify(string $expected, string $payload): bool
    {
        return $expected === '';
    }

    public function algorithmId(): string
    {
        return 'none';
    }

    public function keyId(): null
    {
        return null;
    }
}
