<?php

namespace Shrd\Laravel\JwtTokens\Loaders;

use ArrayAccess;
use ArrayIterator;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use IteratorAggregate;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token as TokenInterface;
use Lcobucci\JWT\UnencryptedToken;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoader;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwtException;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidTestTokenException;
use Shrd\Laravel\JwtTokens\Tokens\Parser;
use Shrd\Laravel\JwtTokens\Tokens\Token;
use Shrd\Laravel\JwtTokens\Validation\Constraints\TestConstraintViolation;
use Traversable;


final class TestTokenLoader implements TokenLoader, IteratorAggregate, ArrayAccess
{
    /**
     * @var array<string, UnencryptedToken>
     */
    protected array $tokens = [];

    public Encoder $encoder;

    public function __construct(?Encoder $encoder = null)
    {
        $this->encoder = $encoder ?? new JoseEncoder;
    }

    /**
     * Creates a new test token loader.
     *
     * @param Encoder|null $encoder
     * @return self
     */
    public static function create(?Encoder $encoder = null): self
    {

        return new self($encoder);
    }

    /**
     * Add a token to the allow list of this test token loader.
     *
     * @param UnencryptedToken $token
     * @param string|null $jwt
     * @return $this
     */
    public function allowToken(UnencryptedToken $token, ?string $jwt = null): self
    {
        $jwt ??= $token->toString();
        $this->tokens[$jwt] = $token;
        return $this;
    }

    /**
     * Removes the provided test token loader from the allow list.
     *
     * @param string|TokenInterface $token
     * @return $this
     */
    public function revokeToken(string|TokenInterface $token): self
    {
        $jwt = is_string($token) ? $token : $token->toString();
        unset($this->tokens[$jwt]);
        return $this;
    }

    /**
     * Clears the allow list of this test token loader.
     *
     * @return $this
     */
    public function revokeAllTokens(): self
    {
        $this->tokens = [];
        return $this;
    }


    /**
     * Creates a new test token, but does not register it (yet) in the loader.
     *
     * @param array|Arrayable $claims
     * @param array|Arrayable $headers
     * @param string|null $signature
     * @param mixed $expiresIn
     * @return Token
     */
    protected function createTestToken(array|Arrayable $claims = [],
                                       array|Arrayable $headers = [],
                                       ?string $signature = null,
                                       mixed $expiresIn = '2 hours'): Token
    {
        if($claims instanceof Arrayable) $claims = $claims->toArray();

        if($expiresIn !== false) {
            $now = Carbon::now();
            $expiresAt = $now->add($expiresIn);

            $claims += [
                "iss" => $now->getTimestamp(),
                "nbf" => $now->getTimestamp(),
                "exp" => $expiresAt->getTimestamp(),
            ];
        }

        if($headers instanceof Arrayable) $headers = $headers->toArray();

        $headers += [
            "typ" => "JWT",
            "alg" => "test"
        ];

        $signature ??= Str::random();

        $encodedClaims = $this->encoder->base64UrlEncode($this->encoder->jsonEncode($claims));
        $encodedHeaders = $this->encoder->base64UrlEncode($this->encoder->jsonEncode($headers));
        $encodedSignature = $this->encoder->base64UrlEncode($signature);

        return new Token(
            new TokenInterface\DataSet($headers, $encodedHeaders),
            new TokenInterface\DataSet($claims, $encodedClaims),
            new TokenInterface\Signature($signature, $encodedSignature),
        );
    }

    /**
     * Creates a new test token and register it in the test token loader.
     *
     * @param array|Arrayable $claims
     * @param array|Arrayable $headers
     * @param string|null $signature
     * @param mixed $expiresIn
     * @return Token
     */
    public function newTestToken(array|Arrayable $headers = [],
                                 array|Arrayable $claims = [],
                                 ?string $signature = null,
                                 mixed $expiresIn = '2 hours'): Token
    {
        $token = $this->createTestToken($claims, $headers, $signature, $expiresIn);

        $this->allowToken($token);

        return $token;
    }

    public function load(string $jwt): UnencryptedToken
    {
        $token = $this->getTestToken($jwt);
        if($token === null) throw new InvalidTestTokenException($jwt, $this);
        return $token;
    }

    public function tryParse(?string $jwt): ?UnencryptedToken
    {
        return $this->getTestToken($jwt);
    }

    public function tryLoad(string $jwt): ?UnencryptedToken
    {
        return $this->getTestToken($jwt);
    }

    /**
     * @throws InvalidTestTokenException
     * @throws InvalidJwtException
     */
    public function parse(string $jwt): UnencryptedToken
    {
        return $this->load($jwt);
    }

    public function check(TokenInterface|string $token): bool
    {
        return $this->getTestToken($token) !== null;
    }

    public function validate(TokenInterface|string $token): UnencryptedToken
    {
        $token = $this->getTestToken($token);
        if($token === null) throw new InvalidTestTokenException($token, $this);
        return $token;
    }

    public function violations(TokenInterface $token): array
    {
        $token = $this->getTestToken($token);
        if($token === null) {
            return [
                new TestConstraintViolation("Token is not a registered test token.", self::class)
            ];
        } else {
            return [];
        }
    }

    public function getTestToken(TokenInterface|string $token): ?UnencryptedToken
    {
        if($token instanceof TokenInterface) {
            if(in_array($token, $this->tokens) && $token instanceof UnencryptedToken) {
                return $token;
            } else {
                $token = $token->toString();
            }
        }

        return $this->tokens[$token] ?? null;
    }

    public function validDateRange(TokenInterface|string $token): DateRange
    {
        $testToken = $this->getTestToken($token);
        if($testToken === null) return DateRange::empty();

        return DateRange::fromBounds(
            lowerBound: $testToken->claims()->get('nbf'),
            upperBound: $testToken->claims()->get('exp')
        );
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->tokens);
    }

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->tokens[$offset]);
    }

    public function offsetGet(mixed $offset): UnencryptedToken
    {
        return $this->tokens[$offset];
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $key = is_string($offset) ? $offset : null;

        if($value instanceof UnencryptedToken) {
            $this->allowToken($value, $key);
        } else if(is_string($value)) {
            $token = Parser::create()->parse($value);
            $this->allowToken($token, $key);
        } else {
            $token = $this->createTestToken($value);
            $this->allowToken($token, $key);
        }
    }

    public function offsetUnset(mixed $offset): void
    {
        $this->revokeToken($offset);
    }
}
