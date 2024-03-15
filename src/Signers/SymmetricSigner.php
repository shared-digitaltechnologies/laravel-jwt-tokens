<?php

namespace Shrd\Laravel\JwtTokens\Signers;

use InvalidArgumentException;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer as AlgorithmImplementation;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Keys\StringSymmetricKey;

/**
 * Wraps a symmetric signing algorithm.
 *
 * @method static self HS256(Key|string $key, ?string $kid = null)
 * @method static self HS384(Key|string $key, ?string $kid = null)
 * @method static self HS512(Key|string $key, ?string $kid = null)
 * @method static self BLAKE2B(Key|string $key, ?string $kid = null)
 */
class SymmetricSigner implements Signer, Verifier
{
    public function __construct(protected AlgorithmImplementation $algorithm,
                                protected Key                     $key,
                                protected ?string                 $kid = null)
    {
    }

    public static function create(AlgorithmImplementation|string $algorithm, Key|string $key, ?string $kid = null): self
    {
        if(is_string($algorithm)) $algorithm = Algorithm::from($algorithm);
        if(is_string($key)) $key = new StringSymmetricKey($key, $kid);
        return new self($algorithm, $key, $kid);
    }

    public static function __callStatic(string $name, array $arguments): self
    {
        $key = $arguments['key'] ?? $arguments[0] ?? throw new InvalidArgumentException("Key missing.");
        $kid = $arguments['kid'] ?? $arguments['keyId'] ?? $arguments[1] ?? null;
        return self::create($name, $key, $kid);
    }

    public function sign(string $payload): string
    {
        return $this->algorithm->sign($payload, $this->key);
    }

    public function verify(string $expected, string $payload): bool
    {
        return $this->algorithm->verify($expected, $payload, $this->key);
    }

    public function algorithmId(): string
    {
        return $this->algorithm->algorithmId();
    }

    public function keyId(): ?string
    {
        if($this->kid !== null) return $this->kid;

        if(method_exists($this->key, 'getKeyId')) {
            return $this->key->getKeyId();
        }

        return null;
    }
}
