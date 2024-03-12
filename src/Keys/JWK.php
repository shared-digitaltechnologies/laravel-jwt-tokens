<?php

namespace Shrd\Laravel\JwtTokens\Keys;

use ArrayAccess;
use ArrayIterator;
use Closure;
use Countable;
use Exceptions\DecodeException;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use InvalidArgumentException;
use IteratorAggregate;
use JsonSerializable;
use LogicException;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;
use Safe\Exceptions\JsonException;
use Shrd\EncodingCombinators\Exceptions\WrappedDecodeException;
use Shrd\EncodingCombinators\Strings\ConstantTime\Base64Url;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwkPropertyException;
use Traversable;

/**
 * @property-read ?string $kty
 * @property-read ?string $crv
 * @property-read ?string $x
 * @property-read ?string $y
 * @property-read ?string $n
 * @property-read ?string $e
 * @property-read ?string $d
 * @property-read ?string $p
 * @property-read ?string $q
 * @property-read ?string $dp
 * @property-read ?string $dq
 * @property-read ?string $qi
 * @property-read ?string $use
 * @property-read ?string[] $key_ops
 * @property-read ?string $alg
 * @property-read ?string $kid
 * @property-read string|string[]|null $x5c
 * @property-read ?string $x5t
 * @property-read ?string $k
 * @implements ArrayAccess<string, mixed>
 * @implements Arrayable<string, mixed>
 * @implements IteratorAggregate<string, mixed>
 */
readonly class JWK implements ArrayAccess, Jsonable, JsonSerializable, Arrayable, Countable, IteratorAggregate, VerificationKey
{
    private function __construct(protected array $attributes)
    {
    }

    /**
     * @throws JsonException
     */
    public static function fromJson(string $value): static
    {
        $value = \Safe\json_decode($value, assoc: true);
        return static::fromAttributes($value);
    }

    public static function fromAttributes(array $attributes): static
    {
        return new static($attributes);
    }

    /**
     * @throws JsonException
     */
    public static function from(string|array|Arrayable|JWK $value): static
    {
        if($value instanceof static) return $value;
        /** @noinspection PhpConditionAlreadyCheckedInspection */
        if($value instanceof JWK) return new static($value->attributes);
        if(is_string($value)) return static::fromJson($value);

        if($value instanceof Arrayable) $value = $value->toArray();
        if(is_array($value)) return static::fromAttributes($value);

        throw new InvalidArgumentException(
            "Cannot convert value of type '".get_debug_type($value)."' to ".static::class
        );
    }

    public function getKeyId(): ?string
    {
        return $this->kid;
    }

    private function couldBeKeyType(KeyType $type): bool
    {
        foreach ($type->requiredPublicJWKProperties() as $property) {
            if(!$this->has($property)) {
                return false;
            }

        }

        $crv = $this->get('crv');
        if($crv !== null && !in_array($crv, $type->allowedCurves())) {
            return false;
        }

        return true;
    }

    public function getKeyType(): KeyType
    {
        $kty = $this->get('kty');
        if($kty !== null) {
            return KeyType::from($kty);
        } else {
            foreach ([KeyType::RSA, KeyType::EC, KeyType::OKP, KeyType::OCT] as $case) {
                if($this->couldBeKeyType($case)) {
                    return $case;
                }
            }
            return KeyType::NONE;
        }
    }

    public function get(string $key, $default = null): mixed
    {
        return $this->attributes[$key] ?? ($default instanceof Closure ? $default($this->attributes) : $default);
    }

    public function __get(string $name)
    {
        return $this->get($name);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->get($offset);
    }

    public function has(string $name): bool
    {
        return isset($this->attributes[$name]);
    }

    public function __isset(string $name): bool
    {
        return $this->has($name);
    }

    public function offsetExists(mixed $offset): bool
    {
        return $this->has($offset);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        throw new LogicException("JWK is readonly");
    }

    public function offsetUnset(mixed $offset): void
    {
        throw new LogicException("JWK is readonly");
    }

    public function toArray(): array
    {
        return $this->attributes;
    }

    public function toString(): string
    {
        return $this->toJson(JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function jsonSerialize(): object
    {
        return (object)$this->toArray();
    }

    public function toJson($options = 0): string
    {
        return json_encode($this->jsonSerialize(), $options);
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->attributes);
    }

    /**
     * @throws InvalidJwkPropertyException
     */
    private function getAsBigIntegerFromBase64Url(string $property): ?BigInteger
    {
        $x = $this->get($property);
        if($x === null) return null;
        try {
            $decoded = Base64Url::decodeNoPadding($x, '=');
        } catch (DecodeException $exception) {
            throw new InvalidJwkPropertyException(
                $this,
                $property,
                message: "Expected '$property to be a Base64Url encoded string",
                previous: $exception
            );
        }
        return new BigInteger($decoded, 256);
    }

    /**
     * @throws InvalidJwkPropertyException
     */
    public function getModulus(): ?BigInteger
    {
        return $this->getAsBigIntegerFromBase64Url('n');
    }

    /**
     * @throws InvalidJwkPropertyException
     */
    public function getExponent(): ?BigInteger
    {
        return $this->getAsBigIntegerFromBase64Url('e');
    }

    public function count(): int
    {
        return count($this->attributes);
    }

    /**
     * @throws InvalidJwkPropertyException
     * @throws WrappedDecodeException
     */
    public function contents(): string
    {
        $keyType = $this->getKeyType();

        return match ($keyType) {
            KeyType::RSA => PublicKeyLoader::loadPublicKey([
                    'n' => $this->getModulus(),
                    'e' => $this->getExponent(),
                ])->toString('PKCS8'),
            KeyType::NONE => '',
            KeyType::OCT => Base64Url::decodeNoPadding($this->k, '='),
            KeyType::OKP => Base64Url::decodeNoPadding($this->x, '='),
            default => PublicKeyLoader::loadPublicKey(
                    json_encode(['keys' => [$this->attributes]])
                )->toString('PKCS8'),
        };
    }

    public function passphrase(): string
    {
        return '';
    }

    public function supportedByAlgorithm(Algorithm $algorithm): bool
    {
        $alg = $this->get('alg');
        if($alg === null) {
            return $this->getKeyType()->isSupportedByAlgorithm($algorithm);
        } else {
            return $alg === $algorithm->value;
        }
    }
}
