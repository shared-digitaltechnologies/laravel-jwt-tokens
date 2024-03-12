<?php

namespace Shrd\Laravel\JwtTokens\Signers;

interface Signer
{
    public function sign(string $payload): string;

    public function algorithmId(): string;

    public function keyId(): ?string;
}
