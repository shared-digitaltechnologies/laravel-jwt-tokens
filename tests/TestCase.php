<?php

namespace Shrd\Laravel\JwtTokens\Tests;

use Orchestra\Testbench\TestCase as BaseTestCase;
use Shrd\Laravel\JwtTokens\JwtService;

class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            'Shrd\Laravel\JwtTokens\ServiceProvider'
        ];
    }

    protected function jwtService(): JwtService
    {
        return $this->app->make(JwtService::class);
    }
}
