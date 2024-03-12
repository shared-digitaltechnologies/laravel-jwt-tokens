<?php

namespace Shrd\Laravel\JwtTokens\Tests;

use Orchestra\Testbench\TestCase as BaseTestCase;

class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            'Shrd\Laravel\JwtTokens\ServiceProvider'
        ];
    }
}
