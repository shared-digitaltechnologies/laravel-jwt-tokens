<?php

namespace Shrd\Laravel\JwtTokens\Tests\Unit\Tokens;

use PHPUnit\Framework\TestCase;
use Shrd\Laravel\JwtTokens\Tokens\CacheLoadedToken;
use Shrd\Laravel\JwtTokens\Tokens\Token;

class CacheLoadedTokenTest extends TestCase
{
    public function test_restores_from_cache_array()
    {
        $token = Token::encode(["typ" => "JWT"], ["sub" => "someClaim"], 'abc');

        $original = CacheLoadedToken::initUsingUnencryptedToken(
            token: $token,
            loaderName: 'loaderName',
            firstLoadedAt: 100
        );

        $this->assertFalse($original->restoredFromCache);

        $cacheLoaded = CacheLoadedToken::restoreCacheArray($original->toCacheArray());

        $this->assertTrue($cacheLoaded->restoredFromCache);
        $this->assertEquals(100, $cacheLoaded->firstLoadedAt);
        $this->assertEquals('loaderName', $cacheLoaded->loaderName);
        $this->assertEquals($token->headers(), $cacheLoaded->headers());
        $this->assertEquals($token->claims(), $cacheLoaded->claims());
        $this->assertEquals($token->signature(), $cacheLoaded->signature());

    }
}
