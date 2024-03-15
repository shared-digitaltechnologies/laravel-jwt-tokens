<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Carbon\CarbonInterval;
use Carbon\FactoryImmutable;
use Closure;
use DateInterval;
use Generator;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ValidAt as ValidAtInterface;
use Psr\Clock\ClockInterface;
use ReflectionClass;
use ReflectionFunction;
use ReflectionMethod;
use ReflectionParameter;
use RuntimeException;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Contracts\IntrospectableConstraintFactory;
use Shrd\Laravel\JwtTokens\Contracts\KeySetResolver;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidatorBuilderFactory;
use Shrd\Laravel\JwtTokens\Exceptions\KeySetLoadException;
use Shrd\Laravel\JwtTokens\Signers\Verifier;
use Shrd\Laravel\JwtTokens\Validation\Builder;

class ConstraintManager implements IntrospectableConstraintFactory, TokenValidatorBuilderFactory
{
    /**
     * @var array<string, Constraint>
     */
    protected array $customConstraints = [];

    /**
     * @var array<string, Closure(Container $app, ...$arguments): Constraint>
     */
    protected array $customConstructors = [];

    /**
     * @var (class-string|object)[]
     */
    protected array $customFactoryClasses = [];


    public function __construct(protected Container         $container,
                                protected ConfigRepository  $config,
                                protected ValidationFactory $validationFactory,
                                protected KeySetResolver    $keySetResolver)
    {
    }

    public function getContainer(): Container
    {
        return $this->container;
    }

    public function setContainer(Container $container): static
    {
        $this->container = $container;
        return $this;
    }

    public function extend(string|object $constraint, callable|Constraint|null $callback = null): static
    {
        if(!is_string($constraint) || $callback === null) {
            $this->customFactoryClasses[] = $constraint;
        } else if($callback instanceof Constraint) {
            $this->customConstraints[Str::camel($constraint)] = $callback;
        } else {
            $this->customConstructors[Str::camel($constraint)] = $callback;
        }

        return $this;
    }

    public function callCustomConstructor(string $constraint, array $arguments): Constraint
    {
        return $this->customConstructors[$constraint]($this->container, ...$arguments);
    }

    protected function customFactories(): Generator
    {
        foreach ($this->customFactoryClasses as $ix => $customFactoryClass) {
            if(is_string($customFactoryClass)) {
                $instance = $this->container->make($customFactoryClass);
                $this->customFactoryClasses[$ix] = $instance;
                yield $instance;
            } else {
                yield $customFactoryClass;
            }
        }
    }

    protected function getClock(): ClockInterface
    {
        if($this->container->has(ClockInterface::class)) {
            return $this->container->make(ClockInterface::class);
        } else {
            return new FactoryImmutable();
        }
    }

    protected function defaultLeeway(): DateInterval
    {
        return $this->toDateInterval($this->config->get('jwt.constraints.leeway', '10 seconds'));
    }

    protected function defaultAudience(): string
    {
        $aud = $this->config->get('jwt.constraints.audience');
        if(!$aud) throw new RuntimeException('No default audience set.');
        return $aud;
    }

    protected function defaultIssuers(): array
    {
        return array_filter(
            $this->config->get('jwt.constraints.issuers', []),
            fn($issuer) => is_string($issuer)
        );
    }

    protected function defaultAlgorithms(): array
    {
        $algorithms = $this->config->get('jwt.constraints.algorithms', [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512
        ]);

        if(is_string($algorithms)) $algorithms = explode(',', $algorithms);

        $result = [];
        foreach ($algorithms as $key => $value) {
            if(is_int($key)) {
                $algs = $value;
            } else {
                $algs = $key;
                if(!$value) continue;
            }

            if(is_string($algs) && Str::contains(',', $algs)) {
                foreach(explode(',', $algs) as $algorithm) {
                    $result[] = $algorithm;
                }
            } else {
                $result[] = $algs;
            }
        }
        return $result;
    }

    protected function toDateInterval(mixed $value): ?DateInterval
    {
        if($value === null) return null;
        if(is_numeric($value)) return CarbonInterval::seconds($value);
        return CarbonInterval::make($value, skipCopy: true);
    }

    public function from(string|Constraint|callable $constraint, ...$arguments): Constraint
    {
        if($constraint instanceof Constraint) return $constraint;
        if(is_string($constraint)) return $this->create($constraint, ...$arguments);
        return $this->createCallbackConstraint($constraint, ...$arguments);
    }

    public function create(string $constraint, ...$arguments): Constraint
    {
        $constraint = Str::camel($constraint);
        if(array_key_exists($constraint, $this->customConstraints)) {
            return $this->customConstraints[$constraint];
        }

        if(array_key_exists($constraint, $this->customConstructors)) {
            return $this->callCustomConstructor($constraint, $arguments);
        }

        foreach ($this->customFactories() as $customFactory) {
            if(method_exists($customFactory, $constraint)) {
                $result = $customFactory->$constraint(...$arguments);

                if(!($result instanceof Constraint)) {
                    throw new RuntimeException(
                        "Method ".get_class($customFactory)."::$constraint() did not return a ".Constraint::class
                    );
                }

                return $result;
            }
        }

        $method = "create".Str::studly($constraint).'Constraint';
        if(method_exists($this, $method)) {
            return $this->$method(...$arguments);
        }

        throw new InvalidArgumentException(
            "Constraint '$constraint' not found."
        );
    }

    public function has(string $constraint): bool
    {
        $constraint = Str::camel($constraint);
        if(array_key_exists($constraint, $this->customConstraints)) return true;
        if(array_key_exists($constraint, $this->customConstructors)) return true;

        foreach ($this->customFactories() as $customFactory) {
            if(method_exists($customFactory, $constraint)) return true;
        }

        $method = "create".Str::studly($constraint).'Constraint';
        if(method_exists($this, $method)) return true;

        return false;
    }

    /**
     * @param string $constraint
     * @return ReflectionParameter[]
     */
    public function getConstraintParameters(string $constraint): array
    {
        $constraint = Str::camel($constraint);
        if(array_key_exists($constraint, $this->customConstraints)) {
            return [];
        }

        if(array_key_exists($constraint, $this->customConstructors)) {
            $reflect = new ReflectionFunction($this->customConstructors[$constraint]);
            return $reflect->getParameters();
        }

        foreach ($this->customFactories() as $customFactory) {
            if(method_exists($customFactory, $constraint)) {
                $reflect = new ReflectionMethod($customFactory, $constraint);
                return $reflect->getParameters();
            }
        }

        $method = "create".Str::studly($constraint).'Constraint';
        if(method_exists($this, $method)) {
            $reflect = new ReflectionMethod($this, $method);
            return $reflect->getParameters();
        }

        throw new InvalidArgumentException(
            "Constraint '$constraint' not found."
        );
    }

    /**
     * @return string[]
     */
    public function customConstraintInstanceNames(): array
    {
        return array_keys($this->customConstraints);
    }

    /**
     * @return string[]
     */
    public function customConstraintConstructorNames(): array
    {
        return array_keys($this->customConstructors);
    }

    /**
     * @return string[]
     */
    public function customFactoryConstraintNames(): array
    {
        $names = [];

        foreach ($this->customFactories() as $customFactory) {
            $reflect = new ReflectionClass($customFactory);
            $methods = $reflect->getMethods(ReflectionMethod::IS_PUBLIC);
            foreach ($methods as $method) {
                $names[] = $method->name;
            }
        }

        return array_unique($names);
    }

    public function customConstraintNames(): array
    {
        return array_unique(
            array_merge(
                $this->customConstraintInstanceNames(),
                $this->customConstraintConstructorNames(),
                $this->customFactoryConstraintNames(),
            )
        );
    }

    public function defaultConstraintNames(): array
    {
        $names = [];

        $reflect = new ReflectionClass($this);
        foreach ($reflect->getMethods() as $method) {
            if(preg_match("/^create([A-Za-z0-9]+)Constraint$/", $method->getName(), $matches)) {
                $names[] = Str::camel($matches[1]);
            }
        }

        return $names;
    }

    public function constraintNames(): array
    {
        return array_unique(
            array_merge(
                $this->customConstraintNames(),
                $this->defaultConstraintNames()
            )
        );
    }

    /** @noinspection PhpUnused */
    public function createValidAtConstraint(bool  $strict = true,
                                            mixed $leeway = null): ValidAtInterface
    {
        $leeway = $this->toDateInterval($leeway) ?? $this->defaultLeeway();
        $clock = $this->getClock();
        return new ValidAt($clock, $leeway, $strict);
    }

    /** @noinspection PhpUnused */
    public function createHasClaimWithValueConstraint(string $claim,
                                                      mixed $value): Constraint\HasClaimWithValue
    {
        return new Constraint\HasClaimWithValue($claim, $value);
    }

    /** @noinspection PhpUnused */
    public function createHasHeaderWithValueConstraint(string $header, mixed $value): HasHeaderWithValue
    {
        return new HasHeaderWithValue($header, $value);
    }

    /** @noinspection PhpUnused */
    public function createIdentifiedByConstraint(string $tid): Constraint\IdentifiedBy
    {
        return new Constraint\IdentifiedBy($tid);
    }

    /** @noinspection PhpUnused */
    public function createIssuedByConstraint(string ...$issuers): Constraint\IssuedBy
    {
        if(count($issuers) === 0) $issuers = $this->defaultIssuers();
        return new Constraint\IssuedBy(...$issuers);
    }

    /** @noinspection PhpUnused */
    public function createPermittedForConstraint(?string $audience = null): Constraint\PermittedFor
    {
        return new Constraint\PermittedFor($audience ?? $this->defaultAudience());
    }

    /** @noinspection PhpUnused */
    public function createRelatedToConstraint(string $subject): Constraint\RelatedTo
    {
        return new Constraint\RelatedTo($subject);
    }

    /**
     * @throws KeySetLoadException
     * @noinspection PhpUnused
     */
    public function createSignedWithConstraint(string ...$keySets): SignedWith
    {
        $keySet = $this->keySetResolver->combine(...$keySets);

        return new SignedWith($keySet);
    }

    /** @noinspection PhpUnused */
    public function createSignedUsingConstraint(string|Algorithm ...$algorithms): SignedUsing
    {
        if(count($algorithms) === 0) $algorithms = $this->defaultAlgorithms();
        $algorithms = array_map(fn($alg) => is_string($alg) ? Algorithm::from($alg) : $alg, $algorithms);
        return new SignedUsing($algorithms);
    }

    /** @noinspection PhpUnused */
    public function createVerifyWithConstraint(Verifier $verifier): VerifyWith
    {
        return new VerifyWith($verifier);
    }

    public function createClaimRulesConstraint(array $rules,
                                               array $messages = [],
                                               array $attributes = []): ClaimRules
    {
        return new ClaimRules(
            validationFactory: $this->validationFactory,
            rules: $rules,
            messages: $messages,
            attributes: $attributes
        );
    }

    /** @noinspection PhpUnused */
    public function createCallbackConstraint(callable $callback,
                                             ?string $message = null): CallbackConstraint
    {
        return new CallbackConstraint($callback, $message);
    }

    /** @noinspection PhpUnused */
    public function createHeaderRulesConstraint(array $rules,
                                                array $messages = [],
                                                array $attributes = []): HeaderRules
    {
        return new HeaderRules(
            validationFactory: $this->validationFactory,
            rules: $rules,
            messages: $messages,
            attributes: $attributes
        );
    }

    /** @noinspection PhpUnused */
    public function createHasClaimsConstraint(string ...$names): HasClaims
    {
        return new HasClaims($names);
    }

    /** @noinspection PhpUnused */
    public function createClaimValuesInConstraint(string $claim, iterable $values): ClaimValuesIn
    {
        return new ClaimValuesIn($claim, $values);
    }

    /** @noinspection PhpUnused */
    public function createHasClaimWithValueInConstraint(string $claim, iterable $values): HasClaimWithValueIn
    {
        return new HasClaimWithValueIn($claim, $values);
    }

    /** @noinspection PhpUnused */
    public function createHasHeaderWithValueInConstraint(string $header, iterable $values): HasHeaderWithValueIn
    {
        return new HasHeaderWithValueIn($header, $values);
    }

    /** @noinspection PhpUnused */
    public function createHasHeadersConstraint(string ...$names): HasHeaders
    {
        return new HasHeaders($names);
    }

    /** @noinspection PhpUnused */
    public function createHasKeyIdConstraint(): HasHeaders
    {
        return new HasHeaders(['kid']);
    }

    /** @noinspection PhpUnused */
    public function createOneOfConstraint(Constraint|array ...$constraints): OneOf
    {
        $resolvedConstraints = [];
        foreach ($constraints as $ix => $constraint) {
            if($constraint instanceof Constraint) {
                $resolvedConstraints[$ix] = $constraint;
            } else{
                $resolvedConstraints[$ix] = $this->create(...$constraint);
            }
        }

        return new OneOf($resolvedConstraints);
    }

    /** @noinspection PhpUnused */
    public function createAlwaysConstraint(): Always
    {
        return new Always;
    }

    /** @noinspection PhpUnused */
    public function createHasNonceValueConstraint(string $nonce): Constraint\HasClaimWithValue
    {
        return new Constraint\HasClaimWithValue('nonce', $nonce);
    }


    public function createValidatorBuilder(): Builder
    {
        return new Builder($this);
    }
}
