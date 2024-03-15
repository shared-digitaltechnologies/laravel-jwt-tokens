<?php

namespace Shrd\Laravel\JwtTokens\Facades;

use DateInterval;
use DateTimeInterface;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Facades\Facade;
use Lcobucci\JWT\Signer as AlgorithmImplementation;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Shrd\Laravel\JwtTokens\Contracts\ConstraintFactory;
use Shrd\Laravel\JwtTokens\Contracts\KeySetLoaderFactory;
use Shrd\Laravel\JwtTokens\Contracts\KeySetResolver;
use Shrd\Laravel\JwtTokens\Contracts\SignerRegistry;
use Shrd\Laravel\JwtTokens\Contracts\TokenBuilderFactory;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoader;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoaderRegistry;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidatorBuilderFactory;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;
use Shrd\Laravel\JwtTokens\JwtService;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Signers\Signer;
use Shrd\Laravel\JwtTokens\Signers\Verifier;
use Shrd\Laravel\JwtTokens\Tokens\Builder;
use Shrd\Laravel\JwtTokens\Validation;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

/**
 * @method static KeySetLoaderFactory keySetLoaders()
 * @method static JwtService keySetLoader(string $prefix, callable $callback)
 *
 * @method static KeySet keys(string ...$descriptors)
 * @method static KeySetResolver keySets()
 *
 * @method static ConstraintFactory constraints()
 * @method static JwtService setConstraintFactory(ConstraintFactory $constraintFactory)
 * @method static JwtService constraint(string|object $constraint, callable|Constraint|null $callback = null)
 *
 * @method static Token\Parser parser()
 * @method static Token parse(string $jwt)
 * @method static Token|null tryParse(string $jwt)
 *
 * @method static TokenValidatorBuilderFactory validators()
 * @method static Validation\Builder validator()
 * @method static Token validate(string|Token $token, ?string $loader = null)
 * @method static bool check(string|Token $token, ?string $loader = null)
 * @method static DateRange validDateRange(string|Token $token, ?string $loader = null)
 *
 * @method static TokenLoaderRegistry loaders()
 * @method static TokenLoader loader(?string $loader = null)
 * @method static string defaultLoader()
 * @method static JwtService setDefaultLoader(string $name)
 * @method static UnencryptedToken load(string $jwt, ?string $loader = null)
 * @method static UnencryptedToken|null tryLoad(string $jwt, ?string $loader = null)
 *
 * @method static SignerRegistry signers()
 * @method static Signer signer(AlgorithmImplementation|string|null $signer = null, Key|KeySet|string|null $key = null, ?string $kid = null)
 * @method static UnencryptedToken sign(ClaimsBag|Arrayable|Token\DataSet|iterable $claims, AlgorithmImplementation|Signer|string|null $signer = null, Key|KeySet|string|null $key = null, ?string $kid = null)
 * @method static Verifier verifier(AlgorithmImplementation|string|null $signer = null, Key|KeySet|string|null $key = null)
 * @method static bool verify(string|Token $token, AlgorithmImplementation|Verifier|string|null $signer = null, Key|KeySet|string|null $key = null)
 *
 * @method static TokenBuilderFactory builders()
 * @method static Builder builder(?string $builder = null)
 * @method static Builder audience(string|string[] $audience)
 * @method static Builder permittedFor(string ...$audiences)
 * @method static Builder nonce(string $nonce)
 * @method static Builder expiresAt(DateTimeInterface|string|int $expiration)
 * @method static Builder expiresIn(DateInterval|string|int|null $interval)
 * @method static Builder identifiedBy(string $id)
 * @method static Builder issuedAt(DateTimeInterface|string|int|null $issuedAt = null)
 * @method static Builder issuedBy(string $issuer)
 * @method static Builder canOnlyBeUsedAfter(DateTimeInterface|string|int|null $notBefore = null)
 * @method static Builder notBefore(DateTimeInterface|string|int|null $notBefore = null)
 * @method static Builder relatedTo(string $subject)
 * @method static Builder subject(string $subject)
 * @method static Builder signedWith(Signer|string|null $signer)
 * @method static Builder withoutSignature()
 * @method static Builder signedUsing(AlgorithmImplementation|string $algorithm, Key|KeySet|string $keySet, string|null $kid = null)
 * @method static Builder withHeader(string $header, mixed $value)
 * @method static Builder withHeaders(Arrayable|iterable $headers)
 * @method static Builder withClaim(string $claim, mixed $value)
 * @method static Builder withClaims(Arrayable|iterable $claims)
 */
class JWT extends Facade
{

    protected static function getFacadeAccessor(): string
    {
        return JwtService::class;
    }
}
