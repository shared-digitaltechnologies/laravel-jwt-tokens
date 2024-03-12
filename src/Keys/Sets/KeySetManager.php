<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets;

use Carbon\CarbonInterval;
use DateInterval;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Shrd\Laravel\JwtTokens\Contracts\KeySetLoader;
use Shrd\Laravel\JwtTokens\Contracts\KeySetResolver;
use Shrd\Laravel\JwtTokens\Exceptions\KeySetLoadException;
use Throwable;

class KeySetManager implements KeySetResolver
{
    /**
     * @var array<string, KeySet>
     */
    protected array $resolvedKeySets = [];


    protected ?CacheRepository $cache = null;
    protected ?string $cachePrefix;
    protected DateInterval $cacheTtl;

    protected array $setConfigs = [];

    public function __construct(protected KeySetLoader $loader,
                                ConfigRepository       $config,
                                CacheFactory           $cacheFactory)
    {
        $cacheEnabled = $config->get('jwt.keys.cache.enabled', false);
        $this->cachePrefix = $config->get('jwt.keys.cache.prefix', 'jwt:key_sets:');
        $this->cacheTtl = CarbonInterval::make($config->get('jwt.keys.cache.ttl') ?? '1 day');

        $this->setConfigs = $config->get('jwt.keys.sets', []);

        if($cacheEnabled) {
            $cacheStore = $config->get('jwt.keys.cache.store');
            $this->cache = $cacheFactory->store($cacheStore);
        }
    }

    public function getLoader(): KeySetLoader
    {
        return $this->loader;
    }

    public function setLoader(KeySetLoader $loader): static
    {
        $this->loader = $loader;
        $this->resolvedKeySets = [];
        return $this;
    }


    /**
     * @throws KeySetLoadException
     */
    public function load(string $descriptor): KeySet
    {
        $config = $this->setConfigs[$descriptor] ?? [];

        try {
            $result = $this->loader->loadKeySet($descriptor, $config);
        } catch (Throwable $exception) {
            throw new KeySetLoadException(
                descriptor: $descriptor,
                previous: $exception
            );
        }

        $this->resolvedKeySets[$descriptor] = $result;
        $this->store($descriptor, $result);

        return $result;
    }

    protected function getCacheKey(string $descriptor): string
    {
        return $this->cachePrefix . sha1($descriptor);
    }

    protected function getCacheTtl(): DateInterval
    {
        return $this->cacheTtl;
    }

    public function restore(string $descriptor): ?KeySet
    {
        return $this->cache?->get(
            $this->getCacheKey($descriptor)
        );
    }

    protected function store(string $descriptor, KeySet $keySet): void
    {
        $this->cache?->set(
            $this->getCacheKey($descriptor),
            new CachedKeySet($keySet),
            $this->getCacheTtl()
        );
    }

    public function forget(string $descriptor): static
    {
        unset($this->resolvedKeySets[$descriptor]);
        $this->cache?->forget($this->getCacheKey($descriptor));
        return $this;
    }

    /**
     * @throws KeySetLoadException
     */
    public function get(string $descriptor): KeySet
    {
        return $this->resolvedKeySets[$descriptor]
            ?? $this->restore($descriptor)
            ?? $this->load($descriptor);
    }

    /**
     * @throws KeySetLoadException
     */
    public function combine(string ...$descriptors): KeySet
    {
        if(count($descriptors) === 0) return new EmptyKeySet;

        if(count($descriptors) === 1) return $this->get($descriptors[0]);

        return new CombinedKeySet(...array_map($this->get(...), $descriptors));
    }
}
