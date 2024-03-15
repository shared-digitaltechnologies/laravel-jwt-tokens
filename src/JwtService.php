<?php

namespace Shrd\Laravel\JwtTokens;

use Exception;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Support\Arrayable;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Signer as AlgorithmImplementation;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoader;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwtException;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;
use Shrd\Laravel\JwtTokens\Exceptions\KeySetLoadException;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Signers\Signer;
use Shrd\Laravel\JwtTokens\Signers\Verifier;
use Shrd\Laravel\JwtTokens\Tokens\Builder;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

/**
 * @mixin Builder
 */
class JwtService
{
    public function __construct(protected Container $container)
    {
    }

    public function keySetLoaders(): Contracts\KeySetLoaderFactory
    {
        return $this->container->make(Contracts\KeySetLoaderFactory::class);
    }

    /**
     * @param string $prefix
     * @param callable(Container $app, Contracts\KeySetLoader $defaultLoader): Contracts\KeySetLoader $callback
     * @return static
     */
    public function keySetLoader(string $prefix, callable $callback): static
    {
        $this->keySetLoaders()->extend($prefix, $callback);
        return $this;
    }

    public function keySets(): Contracts\KeySetResolver
    {
        return $this->container->make(Contracts\KeySetResolver::class);
    }

    /**
     * @throws KeySetLoadException
     */
    public function keys(string ...$descriptors): KeySet
    {
        return $this->keySets()->combine(...$descriptors);
    }

    public function parser(): Parser
    {
        return $this->container->make(Parser::class);
    }

    /**
     * @throws JwtParseException
     */
    public function parse(string $jwt): Token
    {
        $parser = $this->parser();
        try {
            return $parser->parse($jwt);
        } catch (Exception $exception) {
            throw new JwtParseException(
                parser: $parser,
                jwt: $jwt,
                previous: $exception
            );
        }
    }

    public function tryParse(string $jwt): ?Token
    {
        try {
            return $this->parser()->parse($jwt);
        } catch (Exception) {
            return null;
        }
    }

    public function constraints(): Contracts\ConstraintFactory
    {
        return $this->container->make(Contracts\ConstraintFactory::class);
    }

    public function constraint(string|object $constraint, callable|Constraint|null $callback = null): static
    {
        $this->constraints()->extend($constraint, $callback);
        return $this;
    }

    public function validators(): Contracts\TokenValidatorBuilderFactory
    {
        return $this->container->make(Contracts\ConstraintFactory::class);
    }

    public function validator(): Validation\Builder
    {
        return $this->validators()->createValidatorBuilder();
    }

    public function loaders(): Contracts\TokenLoaderRegistry
    {
        return $this->container->make(Contracts\TokenLoaderRegistry::class);
    }

    public function loader(?string $loader = null): TokenLoader
    {
        return $this->loaders()->get($loader);
    }

    public function defaultLoader(): string
    {
        return $this->loaders()->defaultLoader();
    }

    public function setDefaultLoader(string $name): static
    {
        $this->loaders()->setDefaultLoader($name);
        return $this;
    }

    /**
     * @throws InvalidJwtException
     */
    public function load(string $jwt, ?string $loader = null): UnencryptedToken
    {
        return $this->loader($loader)->load($jwt);
    }

    public function tryLoad(string $jwt, ?string $loader = null): ?UnencryptedToken
    {
        return $this->loader($loader)->tryLoad($jwt);
    }

    /**
     * @throws InvalidJwtException
     */
    public function validate(string|Token $token, ?string $loader = null): Token
    {
        return $this->loader($loader)->validate($token);
    }

    public function check(string|Token $token, ?string $loader = null): bool
    {
        return $this->loader($loader)->check($token);
    }

    public function validDateRange(string|Token $token, ?string $loader = null): DateRange
    {
        return $this->loader($loader)->validDateRange($token);
    }

    public function signers(): Contracts\SignerRegistry
    {
        return $this->container->make(Contracts\SignerRegistry::class);
    }

    public function signer(AlgorithmImplementation|string|null $signer = null,
                           Key|KeySet|string|null $key = null,
                           ?string $kid = null): Signer
    {
        if((is_string($signer) && is_null($key)) || is_null($signer)) {
            return $this->signers()->signer($signer);
        } else {
            return $this->signers()->signerUsing($signer, $key, $kid);
        }
    }

    public function sign(ClaimsBag|Arrayable|Token\DataSet|iterable $claims,
                         AlgorithmImplementation|Signer|string|null $signer = null,
                         Key|KeySet|string|null $key = null,
                         ?string $kid = null): UnencryptedToken
    {
        if($claims instanceof Token\DataSet) $claims = $claims->all();
        if($claims instanceof Arrayable) $claims = $claims->toArray();

        $builder = $this->builder()
            ->withClaims($claims);

        if((is_string($signer) && is_null($key))
            || is_null($signer)
            || $signer instanceof Signer) {
            return $builder->sign($signer);
        } else {
            return $builder->signUsing($signer, $key, $kid);
        }
    }

    public function verifier(AlgorithmImplementation|string|null $signer = null,
                             Key|KeySet|string|null $key = null): Verifier
    {
        if(is_null($signer) || is_null($key)) {
            return $this->signers()->verifier($signer);
        } else {
            return $this->signers()->verifierUsing($signer, $key);
        }
    }

    /**
     * @throws JwtParseException
     */
    public function verify(string|Token $token,
                           AlgorithmImplementation|Verifier|string|null $signer = null,
                           Key|KeySet|string|null $key = null): bool
    {
        if(($token instanceof Token) && !($token instanceof UnencryptedToken)) {
            $token = $token->toString();
        }

        if(is_string($token)) {
            $token = $this->parse($token);
        }

        assert($token instanceof UnencryptedToken);

        $verifier = $signer instanceof Verifier ? $signer : $this->verifier($signer, $key);

        return $verifier->verify(
            $token->signature()->toString(),
            $token->payload()
        );
    }

    public function builders(): Contracts\TokenBuilderFactory
    {
        return $this->container->make(Contracts\TokenBuilderFactory::class);
    }

    public function builder(?string $builder = null): Builder
    {
        return $this->builders()->builder($builder);
    }

    public function __call(string $name, array $arguments)
    {
        return $this->builder()->$name(...$arguments);
    }

}
