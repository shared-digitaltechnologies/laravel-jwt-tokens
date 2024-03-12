<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Lcobucci\JWT\Signer as AlgorithmImplementation;
use Lcobucci\JWT\Signer\Key;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Signers\Signer;
use Shrd\Laravel\JwtTokens\Signers\Verifier;

interface SignerRegistry
{
    public function extend(string $driver, callable $callback): static;

    public function signer(?string $signer = null): Signer;

    public function signerUsing(AlgorithmImplementation|string $algorithm,
                                Key|KeySet|string $key,
                                ?string $kid = null): Signer;

    public function verifier(?string $signer = null): Verifier;

    public function verifierUsing(AlgorithmImplementation|string $algorithm,
                                  Key|KeySet|string $key): Verifier;
}
