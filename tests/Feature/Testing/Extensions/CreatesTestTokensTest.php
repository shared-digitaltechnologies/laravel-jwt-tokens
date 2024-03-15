<?php

namespace Shrd\Laravel\JwtTokens\Tests\Feature\Testing\Extensions;


use Shrd\Laravel\JwtTokens\Testing\Extensions\CreatesTestTokens;
use Shrd\Laravel\JwtTokens\Tests\TestCase;

class CreatesTestTokensTest extends TestCase
{
    use CreatesTestTokens;

    public function test_placeholder()
    {
        $this->expectNotToPerformAssertions();
    }
}
