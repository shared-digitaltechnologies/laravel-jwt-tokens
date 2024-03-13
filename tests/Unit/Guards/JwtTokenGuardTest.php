<?php

namespace Shrd\Laravel\JwtTokens\Tests\Unit\Guards;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Signature;
use Mockery;
use Illuminate\Http\Request;
use Lcobucci\JWT\Parser;
use PHPUnit\Framework\TestCase;
use Shrd\Laravel\JwtTokens\Contracts\ClaimsUserProvider;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;
use Shrd\Laravel\JwtTokens\Guards\JwtTokenGuard;
use Shrd\Laravel\JwtTokens\Tokens\Token;

class JwtTokenGuardTest extends TestCase
{
    /**
     * @throws JwtParseException
     */
    public function test_guest_if_authorization_token_is_empty()
    {
        $guard = new JwtTokenGuard(
            name: "token_guard_a",
            parser: Mockery::mock(Parser::class),
            provider: Mockery::mock(ClaimsUserProvider::class),
            request: new Request()
        );

        $this->assertTrue($guard->guest());
    }

    /**
     * @throws JwtParseException
     */
    public function test_throws_authentication_exception_without_token()
    {
        $guard = new JwtTokenGuard(
            name: "token_guard_a",
            parser: Mockery::mock(Parser::class),
            provider: Mockery::mock(ClaimsUserProvider::class),
            request: new Request()
        );

        $this->expectException(AuthenticationException::class);

        $guard->authenticate();
    }

    /**
     * @throws JwtParseException
     */
    public function test_parses_token_and_resolves_user_using_that_token()
    {
        $request = (new Request);
        $request->headers->set('Authorization', 'Bearer AAAA.AAAA.');

        $token = new Token(
            new DataSet([], 'AAAA'),
            new DataSet([], 'AAAA'),
            new Signature('', '')
        );

        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('parse')
            ->with('AAAA.AAAA.')
            ->andReturn($token);

        $user = Mockery::mock(Authenticatable::class);

        $userProvider = Mockery::mock(ClaimsUserProvider::class);
        $userProvider->shouldReceive('retrieveByJwtToken')
            ->with($token)
            ->andReturn($user);

        $guard = new JwtTokenGuard(
            name: "token_guard_a",
            parser: $parser,
            provider: $userProvider,
            request: $request
        );

        $this->assertSame($user, $guard->user());
    }

    /**
     * @throws JwtParseException
     */
    public function test_guest_if_user_does_not_exist()
    {
        $request = (new Request);
        $request->headers->set('Authorization', 'Bearer AAAA.AAAA.');

        $token = new Token(
            new DataSet([], 'AAAA'),
            new DataSet([], 'AAAA'),
            new Signature('', '')
        );

        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('parse')
            ->withAnyArgs()
            ->andReturn($token);

        $userProvider = Mockery::mock(ClaimsUserProvider::class);
        $userProvider->shouldReceive('retrieveByToken')
            ->with($token)
            ->andReturn(null);

        $guard = new JwtTokenGuard(
            name: "token_guard_a",
            parser: $parser,
            provider: $userProvider,
            request: $request
        );

        $this->assertTrue($guard->guest());
    }

    /**
     * @throws JwtParseException
     */
    public function test_retrieves_user_once()
    {
        $request = (new Request);
        $request->headers->set('Authorization', 'Bearer AAAA.AAAA.');

        $token = new Token(
            new DataSet([], 'AAAA'),
            new DataSet([], 'AAAA'),
            new Signature('', '')
        );

        $parser = Mockery::mock(Parser::class);
        $parser->shouldReceive('parse')
            ->withAnyArgs()
            ->andReturn($token);

        $user = Mockery::mock(Authenticatable::class);
        $user
            ->shouldReceive('getAuthIdentifier')
            ->withNoArgs()
            ->andReturn('123');

        $userProvider = Mockery::mock(ClaimsUserProvider::class);
        $userProvider->shouldReceive('retrieveByJwtToken')
            ->once()
            ->with($token)
            ->andReturn($user);

        $guard = new JwtTokenGuard(
            name: "token_guard_a",
            parser: $parser,
            provider: $userProvider,
            request: $request
        );

        $this->assertSame($user, $guard->user());
        $this->assertTrue($guard->check());
        $this->assertFalse($guard->guest());
        $this->assertEquals('123', $guard->id());
    }
}
