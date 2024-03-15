<?php

namespace Shrd\Laravel\JwtTokens\Tests\Unit\Validation;

use Mockery;
use PHPUnit\Framework\TestCase;
use Shrd\Laravel\JwtTokens\Contracts\ConstraintFactory;
use Shrd\Laravel\JwtTokens\Validation\Builder;
use Shrd\Laravel\JwtTokens\Validation\Constraints;

class BuilderTest extends TestCase
{
    public function test_creates_constraints_using_method_name()
    {
        $constraint = new Constraints\Always;

        $constraints = Mockery::mock(ConstraintFactory::class);
        $constraints
            ->shouldReceive('create')
            ->with('someConstraintName', 'arg1', 2, [3, 4])
            ->andReturn($constraint);

        $builder = new Builder($constraints);

        $builder->someConstraintName('arg1', 2, [3,4]);

        $this->assertContains($constraint, $builder->constraints());
    }
}
