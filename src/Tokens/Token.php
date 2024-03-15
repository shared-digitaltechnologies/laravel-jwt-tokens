<?php

namespace Shrd\Laravel\JwtTokens\Tokens;

use ArrayAccess;
use DateTimeInterface;
use Illuminate\Support\Carbon;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\UnencryptedToken;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

readonly class Token implements UnencryptedToken, ArrayAccess
{
    public ClaimsBag $claims;

    private DataSet $_claims;
    private DataSet $_headers;
    private Signature $_signature;

    public function __construct(DataSet   $headers,
                                DataSet   $claims,
                                Signature $signature)
    {
        $this->_claims = $claims;
        $this->_headers = $headers;
        $this->_signature = $signature;
        $this->claims = ClaimsBag::fromDataSet($claims);
    }

    public static function encode(array $headers,
                                  array $claims,
                                  string $signature,
                                  ?Encoder $encoder = null): self
    {
        $encoder ??= new JoseEncoder;

        $encodedHeaders = $encoder->base64UrlEncode($encoder->jsonEncode($headers));
        $encodedClaims = $encoder->base64UrlEncode($encoder->jsonEncode($claims));
        $encodedSignature = $encoder->base64UrlEncode($signature);

        return new self(
            headers: new DataSet($headers, $encodedHeaders),
            claims: new DataSet($claims, $encodedClaims),
            signature: new Signature($signature, $encodedSignature)
        );
    }

    public function claimsBag(): ClaimsBag
    {
        return $this->claims;
    }

    public function headers(): DataSet
    {
        return $this->_headers;
    }

    public function getKeyId(): ?string
    {
        return $this->_headers->get('kid');
    }

    public function hasKeyId(): bool
    {
        return $this->_headers->has('kid');
    }

    public function getTokenType(): ?string
    {
        return $this->_headers->get('typ');
    }

    public function hasTokenType(): ?string
    {
        return $this->_headers->has('typ');
    }

    public function getAlgorithmId(): ?string
    {
        return $this->_headers->get('alg');
    }

    public function requireAlgorithmId(): string
    {
        $alg = $this->_headers->get('alg');
        if($alg === null) throw new InvalidTokenStructure('alg missing');
        return $alg;
    }

    public function hasAlgorithmId(): bool
    {
        return $this->_headers->has('alg');
    }

    public function getAlgorithm(): ?Algorithm
    {
        $alg = $this->getAlgorithmId();
        if($alg === null) return null;
        return Algorithm::tryFromAlgorithmId($alg);
    }

    public function requireAlgorithm(): Algorithm
    {
        return Algorithm::fromAlgorithmId($this->requireAlgorithmId());
    }

    public function hasKnownAlgorithm(): bool
    {
        return $this->getAlgorithm() !== null;
    }

    public function isPermittedFor(string $audience): bool
    {
        return $this->claims->containsAudience($audience);
    }

    public function isIdentifiedBy(string $id): bool
    {
        return $this->claims->getTokenId() === $id;
    }

    public function isRelatedTo(string $subject): bool
    {
        return $this->claims->getSubject() === $subject;
    }

    public function hasBeenIssuedBy(string ...$issuers): bool
    {
        $issuer = $this->claims->getIssuer();
        if($issuer === null) return false;
        return in_array($issuer, $issuers, true);
    }

    public function hasBeenIssuedBefore(DateTimeInterface $now): bool
    {
        return $now >= $this->claims->getIssuedAt();
    }

    public function isMinimumTimeBefore(DateTimeInterface $now): bool
    {
        return $now >= $this->claims->getNotBefore();
    }

    public function isExpired(?DateTimeInterface $now = null): bool
    {
        return (bool)$this->claims->getExpiresAt()?->isBefore($now ?? Carbon::now());
    }

    public function claims(): DataSet
    {
        return $this->_claims;
    }

    public function signature(): Signature
    {
        return $this->_signature;
    }

    public function payload(): string
    {
        return $this->headers()->toString() . '.' . $this->claims()->toString();
    }

    public function toString(): string
    {
        return $this->payload() . '.' . $this->signature()->toString();
    }

    public function __call(string $name, array $arguments)
    {
        return $this->claims->$name(...$arguments);
    }

    public function __get(string $name)
    {
        return $this->claims->get($name);
    }

    public function __set(string $name, $value)
    {
        $this->claims->set($name, $value);
    }

    public function __isset(string $name): bool
    {
        return $this->claims->has($name);
    }

    public function __unset(string $name): void
    {
        $this->claims->unset($name);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function __debugInfo(): array
    {
        return [
            "headers" => $this->_headers->all(),
            "claims" => $this->claims->all()
        ];
    }

    public function offsetExists(mixed $offset): bool
    {
        return $this->claims->offsetExists($offset);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->claims->offsetGet($offset);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->claims->offsetSet($offset, $value);
    }

    public function offsetUnset(mixed $offset): void
    {
        $this->claims->offsetUnset($offset);
    }
}
