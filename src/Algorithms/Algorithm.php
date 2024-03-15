<?php

namespace Shrd\Laravel\JwtTokens\Algorithms;

use Iterator;
use Lcobucci\JWT\Signer as AlgorithmImplementation;
use Lcobucci\JWT\Signer\Key;
use RuntimeException;
use Shrd\Laravel\JwtTokens\Exceptions\UnsupportedAlgorithmException;
use Shrd\Laravel\JwtTokens\Keys\KeyType;
use Shrd\Laravel\JwtTokens\Keys\NoneKey;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Keys\SimpleKey;
use Shrd\Laravel\JwtTokens\Signers\NoneSigner;
use Shrd\Laravel\JwtTokens\Signers\Signer;
use Shrd\Laravel\JwtTokens\Signers\WrappedSigner;
use Shrd\Laravel\JwtTokens\Signers\WrappedVerifier;
use Shrd\Laravel\JwtTokens\Signers\Verifier;

enum Algorithm: string implements AlgorithmImplementation
{
    case HS256 = 'HS256';
    case HS384 = 'HS384';
    case HS512 = 'HS512';

    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';

    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';

    case EdDSA = 'EdDSA';
    case BLAKE2B = 'BLAKE2B';

    case PS256 = 'PS256';
    case PS384 = 'PS384';
    case PS512 = 'PS512';

    case NONE = 'none';

    public static function hasAlgorithmId(string $alg): bool
    {
        foreach (self::cases() as $case) {
            if($case->algorithmId() === $alg) return true;
        }
        return false;
    }

    public static function fromAlgorithmId(string $alg): self
    {
        foreach (self::cases() as $case) {
            if($case->algorithmId() === $alg) return $case;
        }
        throw new UnsupportedAlgorithmException($alg);
    }

    public static function tryFromAlgorithmId(string $alg): ?self
    {
        foreach (self::cases() as $case) {
            if($case->algorithmId() === $alg) return $case;
        }
        return null;
    }

    public static function fromImplementation(AlgorithmImplementation $implementation): self
    {
        if($implementation instanceof self) return $implementation;
        return self::fromAlgorithmId($implementation->algorithmId());
    }

    public static function tryFromImplementation(AlgorithmImplementation $implementation): ?self
    {
        if($implementation instanceof self) return $implementation;
        return self::tryFromAlgorithmId($implementation->algorithmId());
    }

    public static function fromImplOrId(AlgorithmImplementation|string $value): self
    {
        if(is_string($value)) return self::from($value);
        return self::fromImplementation($value);
    }

    public static function tryFromImplOrId(AlgorithmImplementation|string $value): self
    {
        if(is_string($value)) return self::tryFrom($value);
        return self::tryFromImplementation($value);
    }

    public function getHashAlgorithm(): ?string
    {
        return match ($this) {
            self::HS256, self::RS256, self::ES256, self::PS256 => 'sha256',
            self::HS384, self::RS384, self::ES384, self::PS384 => 'sha386',
            self::HS512, self::RS512, self::ES512, self::PS512 => 'sha512',
            default => null
        };
    }

    public function getOpenSSLDigestMethod(): ?string
    {
        return match ($this) {
            self::RS256 => 'RSA-SHA256',
            self::RS384 => 'RSA-SHA384',
            self::RS512 => 'RSA-SHA512',
            default => null
        };
    }

    public function getAlgorithmFamily(): AlgorithmFamily
    {
        return match ($this) {
            self::RS256, self::RS384, self::RS512 => AlgorithmFamily::RSAPKCS1,
            self::PS256, self::PS384, self::PS512 => AlgorithmFamily::RSAPPS,
            self::HS256, self::HS384, self::HS512 => AlgorithmFamily::HMAC,
            self::ES256, self::ES384, self::ES512 => AlgorithmFamily::ECDSA,
            self::EdDSA => AlgorithmFamily::EdDSA,
            self::NONE => AlgorithmFamily::NONE,
            self::BLAKE2B => AlgorithmFamily::BLAKE
        };
    }

    public static function symmetricCases(): Iterator
    {
        foreach (self::cases() as $case) {
            if($case->usesSymmetricKey()) yield $case;
        }
    }

    public static function asymmetricCases(): Iterator
    {
        foreach (self::cases() as $case) {
            if(!$case->usesSymmetricKey()) yield $case;
        }
    }

    public function usesAsymmetricKey(): bool
    {
        return $this->getAlgorithmFamily()->isAsymmetric();
    }

    public function usesSymmetricKey(): bool
    {
        return $this->getAlgorithmFamily()->isSymmetric();
    }

    public function getImplementation(): AlgorithmImplementation
    {
        return match ($this) {
            self::HS256 => new AlgorithmImplementation\Hmac\Sha256,
            self::HS384 => new AlgorithmImplementation\Hmac\Sha384,
            self::HS512 => new AlgorithmImplementation\Hmac\Sha512,
            self::RS256 => new AlgorithmImplementation\Rsa\Sha256,
            self::RS384 => new AlgorithmImplementation\Rsa\Sha384,
            self::RS512 => new AlgorithmImplementation\Rsa\Sha512,
            self::ES256 => new AlgorithmImplementation\Ecdsa\Sha256,
            self::ES384 => new AlgorithmImplementation\Ecdsa\Sha384,
            self::ES512 => new AlgorithmImplementation\Ecdsa\Sha512,
            self::EdDSA => new AlgorithmImplementation\Eddsa,
            self::BLAKE2B => new AlgorithmImplementation\Blake2b,
            self::NONE => new None,
            default => throw new RuntimeException("No signer implemented for algorithm $this->name."),
        };
    }

    public function getKeyType(): KeyType
    {
        return match ($this) {
            self::HS256, self::HS384, self::HS512, self::BLAKE2B => KeyType::OCT,
            self::RS256, self::RS384, self::RS512, self::PS256, self::PS384, self::PS512 => KeyType::RSA,
            self::ES256, self::ES384, self::ES512 => KeyType::EC,
            self::EdDSA => KeyType::OKP,
            self::NONE => KeyType::NONE
        };
    }

    public function minimumBitsLengthForKey(): int
    {
        return match ($this) {
            self::HS256, self::ES256, self::EdDSA, self::BLAKE2B => 256,
            self::HS384, self::ES384 => 384,
            self::HS512 => 512,
            self::ES512 => 521,
            self::RS256, self::RS384, self::RS512, self::PS256, self::PS384, self::PS512 => 2048,
            default => 0
        };
    }

    public function algorithmId(): string
    {
        return $this->name;
    }

    public function sign(string $payload, Key|string $key, ?string $kid = null): string
    {
        if(is_string($key)) {
            $key = $this->createKey($key, $key);
        }

        return $this->getImplementation()->sign($payload, $key);
    }

    public function createKey(string $key, string $passphrase = '', ?string $kid = null): Key
    {
        if($this === self::NONE) {
            return new NoneKey;
        }

        return new SimpleKey($this->getKeyType(), $key, $passphrase, $kid);
    }

    public function signer(Key|string $key, ?string $kid = null): Signer
    {
        if($this === self::NONE) {
            return new NoneSigner();
        }

        if(is_string($key)) {
            $key = new SimpleKey($this->getKeyType(), $key, kid: $kid);
        }

        return new WrappedSigner($this->getImplementation(), $key, $kid);
    }

    public function verify(string $expected, string $payload, Key|string $key): bool
    {
        if(is_string($key)) {
            $key = $this->createKey($key);
        }

        return $this->getImplementation()->verify($expected, $payload, $key);
    }

    public function verifier(Key|KeySet|string $key): Verifier
    {
        if($this === self::NONE) {
            return new NoneSigner();
        }

        if(is_string($key)) {
            $key = new SimpleKey($this->getKeyType(), $key);
        }

        return new WrappedVerifier($this->getImplementation(), $key);
    }
}
