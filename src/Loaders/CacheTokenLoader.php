<?php

namespace Shrd\Laravel\JwtTokens\Loaders;

use Closure;
use Exception;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Events\Dispatcher as EventDispatcher;
use Illuminate\Support\Carbon;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Psr\SimpleCache\InvalidArgumentException;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoader;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidator;
use Shrd\Laravel\JwtTokens\Events\NewTokenLoaded;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwtException;
use Shrd\Laravel\JwtTokens\Loaders\Concerns\WrapsTokenParser;
use Shrd\Laravel\JwtTokens\Loaders\Concerns\WrapsTokenValidator;
use Shrd\Laravel\JwtTokens\Tokens\CacheLoadedToken;

class CacheTokenLoader implements TokenLoader
{
    use WrapsTokenParser;
    use WrapsTokenValidator;

    protected ?TokenValidator $validator = null;

    public function __construct(protected string $name,
                                protected Closure $validatorResolver,
                                protected Parser $parser,
                                protected CacheRepository $cache,
                                protected int $maxCacheTtlSeconds,
                                protected ?EventDispatcher $events = null)
    {
    }

    protected function getCacheKey(string $jwt): string
    {
        return "ctl[$this->name]:$jwt";
    }

    /**
     * @throws InvalidJwtException
     */
    public function load(string $jwt): CacheLoadedToken
    {
        // Try the cache
        $cacheKey = $this->getCacheKey($jwt);
        try {
            $cacheArray = $this->cache->get($cacheKey);
            if($cacheArray !== null) {
                return CacheLoadedToken::restoreCacheArray($cacheArray);
            }
        } catch (InvalidArgumentException) {}


        // Validate the token.
        $validatedToken = $this->validate($jwt);
        assert($validatedToken instanceof UnencryptedToken);

        // Initialize the cache loaded token.
        $now = Carbon::now()->getTimestamp();
        $result = CacheLoadedToken::initUsingUnencryptedToken(
            token: $validatedToken,
            loaderName: $this->name,
            firstLoadedAt: $now
        );

        // Determine the cache ttl.
        $expiresAt = $result->claims()->get('exp');
        if($expiresAt === null) {
            $cacheTtl = $this->maxCacheTtlSeconds;
        } else {
            $cacheTtl = min($expiresAt - $now, $this->maxCacheTtlSeconds);
        }

        // Write the cache array to the cache if the cache ttl is positive.
        if($cacheTtl > 0) {
            try {
                $this->cache->set($cacheKey, $result->toCacheArray());
            } catch (InvalidArgumentException) {}
        }

        // Send new token event.
        $this->events?->dispatch(new NewTokenLoaded($result));

        // Return the result
        return $result;
    }

    public function tryLoad(string $jwt): ?UnencryptedToken
    {
        try {
            return $this->load($jwt);
        } catch (Exception|InvalidJwtException) {
            return null;
        }
    }

    public function parser(): Parser
    {
        return $this->parser;
    }

    public function validator(): TokenValidator
    {
        if($this->validator === null) {
            $this->validator = ($this->validatorResolver)();
        }
        return $this->validator;
    }


}
