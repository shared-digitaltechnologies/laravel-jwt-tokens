<?php

namespace Shrd\Laravel\JwtTokens\Loaders;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher as EventDispatcher;
use Lcobucci\JWT\Parser;
use RuntimeException;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoader;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoaderRegistry;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidator;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidatorBuilderFactory;
use Shrd\Laravel\JwtTokens\Validation\Builder;
use Traversable;

class TokenLoaderManager implements TokenLoaderRegistry
{
    /**
     * @var array<string, TokenLoader|callable(Container $app, string $name): TokenLoader|string>
     */
    protected array $loaders = [];

    protected string $defaultLoader;

    protected int $defaultMaxCacheTtl;

    protected EventDispatcher $events;

    public function __construct(protected Container $container, Repository $config)
    {
        $this->defaultLoader = $config->get(
            'auth.defaults.jwt_loader',
            fn() => $config->get('jwt.loader', 'default')
        );

        $this->events = $this->container->make('events');
        $this->defaultMaxCacheTtl = 60 * 60;
    }

    public function setDefaultLoader(string $name): static
    {
        $this->defaultLoader = $name;
        return $this;
    }

    public function defaultLoader(): string
    {
        return $this->defaultLoader;
    }

    public function register(string $name, string|callable|TokenLoader $loader): static
    {
        $this->loaders[$name] = $loader;
        return $this;
    }

    protected function resolveValidator(TokenValidator|callable $validator): TokenValidator
    {
        if($validator instanceof TokenValidator) return $validator;

        /** @var TokenValidatorBuilderFactory $builderFactory */
        $builderFactory = $this->container->make(TokenValidatorBuilderFactory::class);
        $builder = $builderFactory->createValidatorBuilder();

        $result = $validator($builder, $this->container);

        if($result instanceof Builder) {
            return $result->validator();
        }
        if ($result instanceof TokenValidator) {
            return $result;
        }

        return $builder->validator();
    }

    public function createSimpleLoader(TokenValidator|callable $validator): SimpleTokenLoader
    {
        $parser = $this->container->make(Parser::class);

        return new SimpleTokenLoader($this->resolveValidator($validator), $parser, $this->events);
    }

    public function addSimpleLoader(string $name, TokenValidator|callable $validator): static
    {
        return $this->register($name, fn() => $this->createSimpleLoader($validator));
    }

    public function createEmptyLoader(): EmptyTokenLoader
    {
        return new EmptyTokenLoader;
    }

    public function addEmptyLoader(string $name): static
    {
        return  $this->register($name, $this->createEmptyLoader());
    }

    public function createCacheLoader(string $name,
                                      TokenValidator|callable $validator,
                                      ?string $store = null,
                                      ?int $maxTtlSeconds = null): CacheTokenLoader
    {
        /** @var CacheFactory $cacheFactory */
        $cacheFactory = $this->container->make(CacheFactory::class);
        $cache = $cacheFactory->store($store);

        $maxTtlSeconds ??= $this->defaultMaxCacheTtl;

        return new CacheTokenLoader(
            name: $name,
            validatorResolver: fn() => $this->resolveValidator($validator),
            parser: $this->container->make(Parser::class),
            cache: $cache,
            maxCacheTtlSeconds: $maxTtlSeconds,
            events: $this->events
        );
    }

    /**
     * @param string $name
     * @param TokenValidator|callable(Builder $builder): (TokenValidator|void) $validator
     * @param string|null $store
     * @param int|null $maxTtlSeconds
     * @return $this
     */
    public function addCacheLoader(string $name,
                                   TokenValidator|callable $validator,
                                   ?string $store = null,
                                   ?int $maxTtlSeconds = null): static
    {
        return $this->register($name, fn() => $this->createCacheLoader($name, $validator, $store, $maxTtlSeconds));
    }


    public function has(?string $name): bool
    {
        $name ??= $this->defaultLoader();
        return array_key_exists($name, $this->loaders);
    }

    public function get(?string $name = null): TokenLoader
    {
        $name ??= $this->defaultLoader();
        $loader = $this->loaders[$name];

        if($loader instanceof TokenLoader) return $loader;

        if(is_string($loader)) {
            $loader = $this->container->make($loader);
        } else {
            $loader = $loader($this->container, $name);
        }

        if(!($loader instanceof TokenLoader)) {
            throw new RuntimeException("Token loader '$name' did not resolve to a ".TokenLoader::class);
        }

        $this->loaders[$name] = $loader;

        return $loader;
    }

    public function names(): array
    {
        return array_keys($this->loaders);
    }

    public function getIterator(): Traversable
    {
        foreach ($this->names() as $name) {
            yield $name => $this->get($name);
        }
    }
}
