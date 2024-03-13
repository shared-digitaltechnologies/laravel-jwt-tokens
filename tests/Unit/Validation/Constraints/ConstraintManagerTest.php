<?php

namespace Shrd\Laravel\JwtTokens\Tests\Unit\Validation\Constraints;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use Lcobucci\JWT\Validation\Constraint;
use Mockery;
use PHPUnit\Framework\TestCase;
use Shrd\Laravel\JwtTokens\Contracts\KeySetResolver;
use Shrd\Laravel\JwtTokens\Validation\Constraints\ConstraintManager;

class ConstraintManagerTest extends TestCase
{
    public function test_extend_using_object()
    {
        $constraintManager = new ConstraintManager(
            container: new Container,
            config:  new ConfigRepository,
            validationFactory: Mockery::mock(ValidationFactory::class),
            keySetResolver: Mockery::mock(KeySetResolver::class),
        );

        $testConstraint = Mockery::mock(Constraint::class);

        $mixin = new class($testConstraint)
        {
            public function __construct(protected Constraint $testConstraint)
            {
            }

            public function someTestConstraint(): Constraint
            {
                return $this->testConstraint;
            }
        };

        $constraintManager->extend($mixin);

        $result = $constraintManager->create('some-test-constraint');

        $this->assertSame($testConstraint, $result);
    }

    public function test_extend_using_resolved_object()
    {
        $container = new Container;

        $testConstraint = Mockery::mock(Constraint::class);

        $container->bind('customConstraintFactory', fn() => new class($testConstraint)
        {
            public function __construct(protected Constraint $testConstraint)
            {
            }

            public function someTestConstraint(): Constraint
            {
                return $this->testConstraint;
            }
        });

        $constraintManager = new ConstraintManager(
            container: $container,
            config:  new ConfigRepository,
            validationFactory: Mockery::mock(ValidationFactory::class),
            keySetResolver: Mockery::mock(KeySetResolver::class),
        );

        $constraintManager->extend('customConstraintFactory');

        $result = $constraintManager->create('some-test-constraint');

        $this->assertSame($testConstraint, $result);
    }

    public function test_extend_using_constraint_instance()
    {
        $constraintManager = new ConstraintManager(
            container: new Container,
            config: new ConfigRepository,
            validationFactory: Mockery::mock(ValidationFactory::class),
            keySetResolver: Mockery::mock(KeySetResolver::class)
        );

        $constraint = Mockery::mock(Constraint::class);

        $constraintManager->extend('someTestConstraint', $constraint);

        $result = $constraintManager->create('someTestConstraint');

        $this->assertSame($constraint, $result);
    }

    public function test_extend_using_callback()
    {
        $constraintManager = new ConstraintManager(
            container: new Container,
            config: new ConfigRepository,
            validationFactory: Mockery::mock(ValidationFactory::class),
            keySetResolver: Mockery::mock(KeySetResolver::class)
        );

        $constraint = Mockery::mock(Constraint::class);

        $constraintManager->extend('someTestConstraint', fn() => $constraint);

        $result = $constraintManager->create('someTestConstraint');

        $this->assertSame($constraint, $result);
    }

    public static function defaultConstraintsProvider(): array
    {
        return [
            ['validAt'],
            ['hasClaimWithValue'],
            ['hasHeaderWithValue'],
            ['identifiedBy'],
            ['issuedBy'],
            ['permittedFor'],
            ['relatedTo'],
            ['signedWith'],
            ['signedUsing'],
            ['verifyWith'],
            ['claimRules'],
            ['headerRules'],
            ['callback'],
            ['hasClaims'],
            ['hasHeaders'],
            ['hasKeyId'],
            ['oneOf'],
            ['hasNonceValue'],
            ['always']
        ];
    }

    /**
     * @param string $constraint
     * @return void
     * @dataProvider defaultConstraintsProvider
     */
    public function test_has_default_constraints(string $constraint)
    {
        $constraintManager = new ConstraintManager(
            container: new Container,
            config: new ConfigRepository,
            validationFactory: Mockery::mock(ValidationFactory::class),
            keySetResolver: Mockery::mock(KeySetResolver::class)
        );

        $this->assertTrue($constraintManager->has($constraint), "Has constraint $constraint by default.");
    }

    /**
     * @param string $constraint
     * @return void
     * @dataProvider defaultConstraintsProvider
     */
    public function test_default_constraint_names_contains_constraint(string $constraint)
    {
        $constraintManager = new ConstraintManager(
            container: new Container,
            config: new ConfigRepository,
            validationFactory: Mockery::mock(ValidationFactory::class),
            keySetResolver: Mockery::mock(KeySetResolver::class)
        );

        $this->assertContains($constraint, $constraintManager->defaultConstraintNames());
    }
}
