<?php

namespace Shrd\Laravel\JwtTokens\Tests\Feature\Loaders;


use Shrd\Laravel\JwtTokens\Loaders\CacheTokenLoader;
use Shrd\Laravel\JwtTokens\Loaders\EmptyTokenLoader;
use Shrd\Laravel\JwtTokens\Loaders\SimpleTokenLoader;
use Shrd\Laravel\JwtTokens\Loaders\TokenLoaderManager;
use Shrd\Laravel\JwtTokens\Tests\TestCase;
use Shrd\Laravel\JwtTokens\Tokens\Token;
use Shrd\Laravel\JwtTokens\Validation\Builder;

class TokenLoaderManagerTest extends TestCase
{
    public function test_reads_token_loader_from_auth_config()
    {
        config(['auth.defaults.jwt_loader' => 'my-loader']);

        $loaders = $this->app->make(TokenLoaderManager::class);

        $this->assertEquals('my-loader', $loaders->defaultLoader());
    }

    public function test_register_cache_token_loader_with_callback_validator_builder()
    {
        $loaders = $this->app->make(TokenLoaderManager::class);

        $loaders->addCacheLoader(
            name: 'a',
            validator: fn(Builder $b) => $b->hasClaimWithValue('abc', 'val')
        );

        $loader = $loaders->get('a');

        $this->assertInstanceOf(CacheTokenLoader::class, $loader);

        $tokenA = Token::encode([], ['abc' => 'val'], '');
        $tokenB = Token::encode([], ['abc' => 'laf'], '');

        $this->assertTrue($loader->check($tokenA));
        $this->assertFalse($loader->check($tokenB));
    }

    public function test_register_simple_token_loader_with_callback_validator_builder()
    {
        $loaders = $this->app->make(TokenLoaderManager::class);

        $loaders->addSimpleLoader(
            name: 'a',
            validator: fn(Builder $b) => $b->hasClaimWithValue('abc', 'val')
        );

        $loader = $loaders->get('a');

        $this->assertInstanceOf(SimpleTokenLoader::class, $loader);

        $tokenA = Token::encode([], ['abc' => 'val'], '');
        $tokenB = Token::encode([], ['abc' => 'laf'], '');

        $this->assertTrue($loader->check($tokenA));
        $this->assertFalse($loader->check($tokenB));
    }

    public function test_register_empty_loader()
    {
        $loaders = $this->app->make(TokenLoaderManager::class);

        $loaders->addEmptyLoader(name: 'a');

        $loader = $loaders->get('a');

        $this->assertInstanceOf(EmptyTokenLoader::class, $loader);

        $token = Token::encode([], ['abc' => 'val'], '');

        $this->assertFalse($loader->check($token));
    }
}
