<?php

namespace Shrd\Laravel\JwtTokens\Tokens\Claims;

use ArrayAccess;
use ArrayIterator;
use Closure;
use Countable;
use Exceptions\DecodeErrorException;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Support\Arr;
use Illuminate\Support\Traits\Macroable;
use IteratorAggregate;
use JsonSerializable;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\UnencryptedToken;
use Safe\Exceptions\JsonException;
use Shrd\EncodingCombinators\Strings\Base64Url;
use Shrd\Laravel\JwtTokens\Exceptions\ClaimMissingException;
use Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns\ClaimsBagHasAzureHelpers;
use Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns\ClaimsBagHasCollectionClaims;
use Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns\ClaimsBagHasOpenIdHelpers;
use Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns\ClaimsBagHasRfc7619Helpers;
use Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns\ClaimsBagHasRfc7643Helpers;
use Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns\ClaimsBagHasScopes;
use Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns\ClaimsBagHasTimestampClaims;
use stdClass;
use Stringable;
use Traversable;

/**
 * @implements Arrayable<string, mixed>
 * @implements ArrayAccess<string, mixed>
 * @implements IteratorAggregate<string, mixed>
 */
class ClaimsBag implements Arrayable, ArrayAccess, Jsonable, JsonSerializable, IteratorAggregate, Stringable, Countable
{
    use Macroable,
        ClaimsBagHasCollectionClaims,
        ClaimsBagHasTimestampClaims,
        ClaimsBagHasScopes,
        ClaimsBagHasRfc7619Helpers,
        ClaimsBagHasRfc7643Helpers,
        ClaimsBagHasOpenIdHelpers,
        ClaimsBagHasAzureHelpers;

    private function __construct(protected array $claims)
    {
    }

    /**
     * @param iterable<string, mixed> $claims
     * @return static
     */
    public static function create(iterable $claims = []): static
    {
        return new static(iterator_to_array($claims));
    }

    public function isEmpty(): bool
    {
        return $this->count() === 0;
    }

    /**
     * Merges multiple claims bags together in one claims bag.
     *
     * @param self|Arrayable|iterable|string|DataSet|UnencryptedToken|null ...$bags
     * @return static
     */
    public static function merge(self|Arrayable|iterable|string|DataSet|UnencryptedToken|null ...$bags): static
    {
        if(count($bags) === 0) return self::empty();
        $firstBag = array_shift($bags);
        return static::coerce($firstBag)->append(...$bags);
    }

    /**
     * Tries to convert the provided value inta a Claims Bag. Just returns the value itself if it already is a
     * ClaimsBag.
     *
     * @param ClaimsBag|Arrayable|iterable|DataSet|string|UnencryptedToken|null $value
     * @return static
     */
    public static function coerce(self|Arrayable|iterable|string|DataSet|UnencryptedToken|null $value): static
    {
        if($value instanceof static) return $value;
        return static::from($value);
    }

    public static function fromDataSet(DataSet $dataSet): static
    {
        return new static($dataSet->all(), []);
    }

    public static function fromUnencryptedToken(UnencryptedToken $token): static
    {
        return self::fromDataSet($token->claims());
    }

    /**
     * @throws JsonException
     * @throws DecodeErrorException
     */
    public static function fromEncodedJson(string $encodedJson): static
    {
        return self::fromJson(Base64Url::decode($encodedJson));
    }

    /**
     * @throws JsonException
     */
    public static function fromJson(string $json): static
    {
        $claims = \Safe\json_decode($json, assoc: true);
        return new static($claims);
    }

    /**
     * Creates a new claims bag from the provided value.
     *
     * @param Arrayable|iterable|DataSet|UnencryptedToken|null $value
     * @return static
     */
    public static function from(Arrayable|iterable|DataSet|UnencryptedToken|null $value): static
    {
        if($value instanceof self) return new static($value->all());
        if($value instanceof DataSet) return static::fromDataSet($value);
        if($value instanceof UnencryptedToken) return static::fromUnencryptedToken($value);
        if($value === null) $value = [];
        if($value instanceof Arrayable) $value = $value->toArray();
        return static::create($value);
    }

    /**
     * Creates a new empty claims bag.
     *
     * @return static
     */
    public static function empty(): static
    {
        return new static([]);
    }

    /**
     * @throws ClaimMissingException
     */
    public function ensureClaimsExist(array $mandatoryClaims): static
    {
        foreach ($mandatoryClaims as $mandatoryClaim) {
            if(!$this->has($mandatoryClaim)) {
                throw new ClaimMissingException($mandatoryClaim, $this);
            }
        }
        return $this;
    }

    /**
     * Returns an array of the claims that can be used as telemetry attributes.
     *
     * @param string $prefix A prefix for the attribute keys.
     * @return array<string, string>
     */
    public function getTraceAttributes(string $prefix = 'user.claims.'): array
    {
        $result = [];
        foreach ($this->all() as $key => $claim) {
            $serializedClaim = is_string($claim) ? $claim : json_encode($claim, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            $result[$prefix . $key] = $serializedClaim;
        }
        return $result;
    }

    public function get(string $name, $default = null): mixed
    {
        if(array_key_exists($name, $this->claims)) {
            return $this->claims[$name];
        }

        return $default instanceof Closure ? $default($this->claims) : $default;
    }

    /**
     * @throws ClaimMissingException
     */
    public function require(string $name): mixed
    {
        if(!$this->has($name)) {
            throw new ClaimMissingException(
                claimName: $name,
                claims: $this
            );
        }

        return $this->get($name);
    }

    /**
     * Sets a claim the claims bag to the provided value.
     *
     * IMPORTANT! This method will mutate the current claims bag.
     *
     * @param string $name
     * @param mixed $value
     * @return $this
     */
    public function set(string $name, mixed $value): static
    {
        $this->claims[$name] = $value;
        return $this;
    }

    /**
     * Fills this claims bag with the provided values.
     *
     * IMPORTANT! This method will mutate the current claims bag!
     *
     * @param iterable|Arrayable $values
     * @return $this
     */
    public function fill(iterable|Arrayable $values): static
    {
        if($values instanceof Arrayable) $values = $values->toArray();

        foreach ($values as $name => $value) {
            $this->set($name, $value);
        }
        return $this;
    }

    /**
     * Deletes a claim form this claims bag.
     *
     * IMPORTANT! This method will mutate the claims bag.
     *
     * @param string $name
     * @return $this
     */
    public function unset(string $name): static
    {
        unset($this->claims[$name]);
        return $this;
    }

    /**
     * Returns a new ClaimsBag with the provided claim added.
     *
     * @param string $name
     * @param mixed $value
     * @return static
     */
    protected function withClaim(string $name, mixed $value): static
    {
        $newClaims = $this->all();
        $newClaims[$name] = $value;

        return new static($newClaims);
    }

    /**
     * Returns a new ClaimsBag with the provided claims added.
     *
     * @param iterable|Arrayable $claims
     * @return static
     */
    protected function withClaims(iterable|Arrayable $claims): static
    {
        if($claims instanceof Arrayable) $claims = $claims->toArray();
        return new static(array_merge($this->all(), iterator_to_array($claims)));
    }

    /**
     * Convenience function that combines withClaims and withClaim. Added for consistency with laravel APIs.
     *
     * @param iterable|Arrayable|ClaimsBag|DataSet|UnencryptedToken|string|null $claimOrClaims
     * @param mixed|null $value
     * @return static
     */
    public function with(iterable|Arrayable|self|DataSet|UnencryptedToken|string|null $claimOrClaims,
                         mixed $value = null): static
    {
        if(is_string($claimOrClaims)) return $this->withClaim($claimOrClaims, $value);

        if($claimOrClaims instanceof self
            || $claimOrClaims instanceof UnencryptedToken) return $this->append($claimOrClaims);

        else return $this->withClaims($claimOrClaims);
    }

    /**
     * Creates a new ClaimsBag with all the values overwritten by the provided claims.
     *
     * @param ClaimsBag|iterable|Arrayable|DataSet|UnencryptedToken|null ...$bags
     * @return static
     */
    public function append(self|iterable|Arrayable|DataSet|UnencryptedToken|null ...$bags): static
    {
        $newClaims = $this->all();

        foreach ($bags as $bag) {
            $bag = self::coerce($bag);
            foreach ($bag->all() as $name => $value) {
                $newClaims[$name] = $value;
            }
        }

        return new static($newClaims);
    }


    /**
     * Returns a new ClaimsBag without the provided claim.
     *
     * @param string ...$names
     * @return static
     */
    public function without(string ...$names): static
    {
        return new static(Arr::except($this->claims, $names));
    }


    /**
     * Returns whether this claims bag has a claim with the provided name.
     *
     * @param string $name
     * @return bool
     */
    public function has(string $name): bool
    {
        return isset($this->claims[$name]);
    }

    /**
     * Returns whether this claims bag has all claims with the provided names.
     *
     * @param iterable|string ...$names
     * @return bool
     */
    public function hasAll(iterable|string ...$names): bool
    {
        foreach ($names as $name) {
            if(is_iterable($name)) {
                foreach ($name as $item) {
                    if(!$this->has($item)) return false;
                }
            } else {
                if(!$this->has($name)) return false;
            }
        }

        return true;
    }

    /**
     * Returns a new claims bag with only the provided claims.
     *
     * @param iterable|string ...$names
     * @return $this
     */
    public function only(iterable|string ...$names): static
    {
        $result = [];
        foreach ($names as $items) {
            if(!is_iterable($items)) $items = [$items];
            foreach ($items as $name) {
                if($this->has($name)) {
                    $result[$name] = $this->get($name);
                }
            }
        }
        return new static($result);
    }

    public function all(): array
    {
        return $this->claims;
    }

    /**
     * @return string[]
     */
    public function keys(): array
    {
        return array_keys($this->all());
    }

    public function toArray(): array
    {
        return $this->all();
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->all());
    }

    public function offsetExists(mixed $offset): bool
    {
        return $this->has($offset);
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->get($offset);
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->set($offset, $value);
    }

    public function offsetUnset(mixed $offset): void
    {
        $this->unset($offset);
    }

    public function __get(string $name)
    {
        return $this->get($name);
    }

    public function __set(string $name, $value): void
    {
        $this->set($name, $value);
    }

    public function __isset(string $name): bool
    {
        return $this->has($name);
    }

    public function __unset(string $name): void
    {
        $this->offsetUnset($name);
    }

    public final function toJson($options = 0): string
    {
        return json_encode($this->jsonSerialize(), $options);
    }

    public final function jsonSerialize(): stdClass
    {
        return (object)$this->all();
    }

    public function toString(): string
    {
        return Base64Url::encode($this->toJson(JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function toDataSet(): DataSet
    {
        return new DataSet($this->all(), $this->toString());
    }

    public final function count(): int
    {
        return count($this->all());
    }
}
