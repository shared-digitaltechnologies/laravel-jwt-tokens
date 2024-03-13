<?php

namespace Shrd\Laravel\JwtTokens;

use Carbon\FactoryImmutable;
use Exception;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Psr\Clock\ClockInterface;
use Shrd\Laravel\JwtTokens\Contracts\ConstraintFactory;
use Shrd\Laravel\JwtTokens\Contracts\KeySetLoader;
use Shrd\Laravel\JwtTokens\Contracts\KeySetLoaderFactory;
use Shrd\Laravel\JwtTokens\Contracts\KeySetResolver;
use Shrd\Laravel\JwtTokens\Contracts\SignerRegistry;
use Shrd\Laravel\JwtTokens\Contracts\TokenBuilderFactory;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidatorFactory;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;
use Shrd\Laravel\JwtTokens\Exceptions\KeySetLoadException;
use Shrd\Laravel\JwtTokens\Keys\Loaders\KeySetLoaderManager;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySetManager;
use Shrd\Laravel\JwtTokens\Signers\Signer;
use Shrd\Laravel\JwtTokens\Signers\SignerManager;
use Shrd\Laravel\JwtTokens\Signers\Verifier;
use Shrd\Laravel\JwtTokens\Tokens\Builder;
use Shrd\Laravel\JwtTokens\Tokens\BuilderFactory;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;
use Shrd\Laravel\JwtTokens\Validation\Constraints\ConstraintManager;
use Shrd\Laravel\JwtTokens\Validation\TokenValidator;

class JwtService implements TokenValidatorFactory
{
    protected SignerRegistry $signerRegistry;

    protected KeySetResolver $keySetResolver;

    protected KeySetLoaderFactory $keySetLoaderFactory;

    protected ConstraintFactory $constraintFactory;

    protected TokenBuilderFactory $builderFactory;

    public function __construct(Container                 $container,
                                ConfigRepository          $config,
                                CacheFactory              $cache,
                                ValidationFactory         $validationFactory,
                                Encoder                   $encoder,
                                protected ParserInterface $parser,
                                ?ClockInterface           $clock = null)
    {
        $clock ??= new FactoryImmutable;

        $this->keySetLoaderFactory = new KeySetLoaderManager($container);

        $this->keySetResolver = new KeySetManager(
            loader: $this->keySetLoaderFactory,
            config: $config,
            cacheFactory: $cache
        );

        $this->constraintFactory = new ConstraintManager(
            container: $container,
            config: $config,
            validationFactory: $validationFactory,
            keySetResolver: $this->keySetResolver,
        );

        $this->signerRegistry = new SignerManager(
            container: $container,
            keySetResolver: $this->keySetResolver,
            config: $config
        );

        $this->builderFactory = new BuilderFactory(
            signerRegistry: $this->signerRegistry,
            keySetResolver: $this->keySetResolver,
            clock: $clock,
            encoder: $encoder,
            config: $config,
        );
    }


    public function keySetLoaders(): KeySetLoaderFactory
    {
        return $this->keySetLoaderFactory;
    }

    /**
     * @param string $prefix
     * @param callable(Container $app, KeySetLoader $defaultLoader): KeySetLoader $callback
     * @return static
     */
    public function keySetLoader(string $prefix, callable $callback): static
    {
        $this->keySetLoaderFactory->extend($prefix, $callback);
        return $this;
    }

    public function keySets(): KeySetResolver
    {
        return $this->keySetResolver;
    }

    /**
     * @throws KeySetLoadException
     */
    public function keys(string ...$descriptors): KeySet
    {
        return $this->keySetResolver->combine(...$descriptors);
    }

    /**
     * @throws JwtParseException
     */
    public function parse(string $jwt): Token
    {
        try {
            return $this->parser->parse($jwt);
        } catch (Exception $exception) {
            throw new JwtParseException(
                parser: $this->parser,
                jwt: $jwt,
                previous: $exception
            );
        }
    }

    public function tryParse(string $jwt): ?Token
    {
        try {
            return $this->parser->parse($jwt);
        } catch (Exception) {
            return null;
        }
    }

    public function setKeySetLoaderFactory(KeySetLoaderFactory $keySetLoaderFactory): static
    {
        $this->keySetLoaderFactory = $keySetLoaderFactory;
        if(method_exists($this->keySetResolver, 'setLoader')) {
            $this->keySetResolver->setLoader($keySetLoaderFactory);
        }
        return $this;
    }

    public function setConstraintFactory(ConstraintFactory $constraintFactory): static
    {
        $this->constraintFactory = $constraintFactory;
        return $this;
    }

    public function setKeySetResolver(KeySetResolver $keySetResolver): static
    {
        $this->keySetResolver = $keySetResolver;
        if(method_exists($this->constraintFactory, 'setKeySetResolver')) {
            $this->constraintFactory->setKeySetResolver($keySetResolver);
        }
        if(method_exists($this->signerRegistry, 'setKeySetResolver')) {
            $this->signerRegistry->setKeySetResolver($keySetResolver);
        }
        if(method_exists($this->builderFactory, 'setKeySetResolver')) {
            $this->builderFactory->setKeySetResolver($keySetResolver);
        }
        return $this;
    }

    public function setSignerRegistry(SignerRegistry $signerRegistry): static
    {
        $this->signerRegistry = $signerRegistry;
        if(method_exists($this->builderFactory, 'setSignerRegistry')) {
            $this->builderFactory->setSignerRegistry($signerRegistry);
        }
        return $this;
    }




    public function constraints(): ConstraintFactory
    {
        return $this->constraintFactory;
    }

    public function constraint(string|object $constraint, callable|Constraint|null $callback = null): static
    {
        $this->constraintFactory->extend($constraint, $callback);
        return $this;
    }

    /**
     * @throws JwtParseException
     */
    public function validate(string|Token $token): TokenValidator
    {
        if(is_string($token)) {
            $token = $this->parse($token);
        }
        return new TokenValidator($token, $this->constraintFactory);
    }

    public function signers(): SignerRegistry
    {
        return $this->signerRegistry;
    }

    public function signer(string|null $signer = null): Signer
    {
        return $this->signers()->signer($signer);
    }

    public function sign(ClaimsBag|Arrayable|Token\DataSet|iterable $claims,
                         Signer|string|null $signer = null): UnencryptedToken
    {
        if($claims instanceof Token\DataSet) $claims = $claims->all();
        if($claims instanceof Arrayable) $claims = $claims->toArray();

        return $this->builder()
            ->withClaims($claims)
            ->sign($signer);
    }

    public function verifier(string|null $signer = null): Verifier
    {
        return $this->signers()->verifier($signer);
    }

    /**
     * @throws JwtParseException
     */
    public function verify(string|Token $token, Verifier|string|null $signer = null): bool
    {
        if(($token instanceof Token) && !($token instanceof UnencryptedToken)) {
            $token = $token->toString();
        }

        if(is_string($token)) {
            $token = $this->parse($token);
        }

        assert($token instanceof UnencryptedToken);

        $verifier = $signer instanceof Verifier ? $signer : $this->verifier($signer);

        return $verifier->verify(
            $token->signature()->toString(),
            $token->payload()
        );
    }

    public function builders(): TokenBuilderFactory
    {
        return $this->builderFactory;
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
