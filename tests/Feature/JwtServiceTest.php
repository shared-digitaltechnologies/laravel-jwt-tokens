<?php

namespace Shrd\Laravel\JwtTokens\Tests\Feature;

use Lcobucci\JWT\Parser;
use Shrd\Laravel\JwtTokens\Contracts;
use Shrd\Laravel\JwtTokens\Validation;
use Shrd\Laravel\JwtTokens\Tokens;
use Shrd\Laravel\JwtTokens\Tests\TestCase;

class JwtServiceTest extends TestCase
{
    public function test_resolves_keySetLoaders()
    {
        $this->assertInstanceOf(
           Contracts\KeySetLoaderFactory::class,
            $this->jwtService()->keySetLoaders()
        );
    }

    public function test_resolves_keySets()
    {
        $this->assertInstanceOf(
            Contracts\KeySetResolver::class,
            $this->jwtService()->keySets()
        );
    }

    public function test_resolves_parser()
    {
        $this->assertInstanceOf(
            Parser::class,
            $this->jwtService()->parser()
        );
    }

    public function test_resolves_constraints()
    {
        $this->assertInstanceOf(
            Contracts\ConstraintFactory::class,
            $this->jwtService()->constraints()
        );
    }

    public function test_resolves_validators()
    {
        $this->assertInstanceOf(
            Contracts\TokenValidatorBuilderFactory::class,
            $this->jwtService()->validators()
        );
    }

    public function test_resolves_loaders()
    {
        $this->assertInstanceOf(
            Contracts\TokenLoaderRegistry::class,
            $this->jwtService()->loaders()
        );
    }

    public function test_resolves_signers()
    {
        $this->assertInstanceOf(
            Contracts\SignerRegistry::class,
            $this->jwtService()->signers()
        );
    }

    public function test_resolves_builders()
    {
        $this->assertInstanceOf(
            Contracts\TokenBuilderFactory::class,
            $this->jwtService()->builders()
        );
    }

    public function test_creates_validator_builders()
    {
        $this->assertInstanceOf(
            Validation\Builder::class,
            $this->jwtService()->validator()
        );
    }

    public function test_creates_token_builders()
    {
        $this->assertInstanceOf(
            Tokens\Builder::class,
            $this->jwtService()->builder()
        );
    }
}
