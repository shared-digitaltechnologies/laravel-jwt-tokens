<?php

namespace Shrd\Laravel\JwtTokens\Tests\Unit\Guards;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Mockery;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use Shrd\Laravel\JwtTokens\Contracts\ClaimsUserProvider;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoader;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwtException;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;
use Shrd\Laravel\JwtTokens\Guards\JwtTokenGuard;
use Shrd\Laravel\JwtTokens\Tokens\Token;

class JwtTokenGuardTest extends TestCase
{
    /**
     * @throws InvalidJwtException
     */
    public function test_guest_if_authorization_token_is_empty()
    {
        $guard = new JwtTokenGuard(
            name: "token_guard_a",
            loader: Mockery::mock(TokenLoader::class),
            provider: Mockery::mock(ClaimsUserProvider::class),
            request: new Request()
        );

        $this->assertTrue($guard->guest());
    }

    /**
     * @throws JwtParseException
     * @throws InvalidJwtException
     */
    public function test_throws_authentication_exception_without_token()
    {
        $guard = new JwtTokenGuard(
            name: "token_guard_a",
            loader: Mockery::mock(TokenLoader::class),
            provider: Mockery::mock(ClaimsUserProvider::class),
            request: new Request()
        );

        $this->expectException(AuthenticationException::class);

        $guard->authenticate();
    }

    /**
     * @throws InvalidJwtException
     */
    public function test_parses_token_and_resolves_user_using_that_token()
    {
        $token = Token::encode(
            headers: ["typ" => "JWT"],
            claims: [],
            signature: ''
        );

        $request = (new Request);
        $request->headers->set('Authorization', "Bearer AAAA.AAAA.");

        $loader = Mockery::mock(TokenLoader::class);
        $loader->shouldReceive('load')
            ->with('AAAA.AAAA.')
            ->andReturn($token);

        $user = Mockery::mock(Authenticatable::class);

        $provider = Mockery::mock(ClaimsUserProvider::class);
        $provider->shouldReceive('retrieveByClaims')
            ->withAnyArgs()
            ->andReturn($user);

        $guard = new JwtTokenGuard(
            name: "token_guard_a",
            loader: $loader,
            provider: $provider,
            request: $request
        );

        $this->assertSame($user, $guard->user());
    }

    /**
     * @throws InvalidJwtException
     */
    public function test_guest_if_user_does_not_exist()
    {
        $token = Token::encode([], [], '');

        $request = (new Request);
        $request->headers->set('Authorization', 'Bearer AAAA.AAAA.');

        $loader = Mockery::mock(TokenLoader::class);
        $loader->shouldReceive('load')
            ->with('AAAA.AAAA.')
            ->andReturn($token);

        $userProvider = Mockery::mock(ClaimsUserProvider::class);
        $userProvider->shouldReceive('retrieveByClaims')
            ->withAnyArgs()
            ->andReturn(null);

        $guard = new JwtTokenGuard(
            name: "token_guard_a",
            loader: $loader,
            provider: $userProvider,
            request: $request
        );

        $this->assertTrue($guard->guest());
    }

    /**
     * @throws InvalidJwtException
     */
    public function test_retrieves_user_once()
    {

        $request = (new Request);
        $request->headers->set('Authorization', 'Bearer AAAA.AAAA.');

        $token = Token::encode([], [], '');

        $loader = Mockery::mock(TokenLoader::class);
        $loader->shouldReceive('load')
            ->with('AAAA.AAAA.')
            ->andReturn($token);

        $user = Mockery::mock(Authenticatable::class);
        $user
            ->shouldReceive('getAuthIdentifier')
            ->withNoArgs()
            ->andReturn('123');

        $userProvider = Mockery::mock(ClaimsUserProvider::class);
        $userProvider->shouldReceive('retrieveByClaims')
            ->once()
            ->withAnyArgs()
            ->andReturn($user);

        $guard = new JwtTokenGuard(
            name: "token_guard_a",
            loader: $loader,
            provider: $userProvider,
            request: $request
        );

        $this->assertSame($user, $guard->user());
        $this->assertTrue($guard->check());
        $this->assertFalse($guard->guest());
        $this->assertEquals('123', $guard->id());
    }
}
