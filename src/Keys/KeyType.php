<?php

namespace Shrd\Laravel\JwtTokens\Keys;

use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;

enum KeyType: string
{
    case EC = 'EC';
    case RSA = 'RSA';
    case OKP = 'OKP';
    case OCT = 'oct';
    case NONE = 'none';

    public function isSupportedByAlgorithm(Algorithm $algorithm): bool
    {
        return $this === $algorithm->getKeyType();
    }

    public function requiredPublicJWKProperties(): array
    {
        return match ($this) {
            self::EC => ['x', 'y', 'crv'],
            self::OKP => ['x', 'crv'],
            self::RSA => ['n', 'e'],
            self::OCT => ['k'],
            self::NONE => [],
        };
    }

    public function allowedCurves(): array
    {
        return match ($this) {
            self::EC => ['P-256', 'P-384', 'P-521', 'secp256k1'],
            self::OKP => ['Ed25519', 'Ed448'],
            default => [],
        };
    }
}
