<?php

namespace Shrd\Laravel\JwtTokens\Tokens;

use Carbon\CarbonInterval;
use DateInterval;
use Illuminate\Contracts\Config\Repository;
use InvalidArgumentException;
use Lcobucci\JWT\Encoder;
use Psr\Clock\ClockInterface;
use Shrd\Laravel\JwtTokens\Contracts\KeySetResolver;
use Shrd\Laravel\JwtTokens\Contracts\SignerRegistry;
use Shrd\Laravel\JwtTokens\Contracts\TokenBuilderFactory;

class BuilderFactory implements TokenBuilderFactory
{
    protected DateInterval|null $defaultExpiresIn;

    /**
     * @var class-string<Builder>
     */
    protected string $builderClass;

    protected array $builderConfigs = [];

    protected string $defaultBuilder;

    public function __construct(protected SignerRegistry $signerRegistry,
                                protected KeySetResolver $keySetResolver,
                                protected ClockInterface $clock,
                                protected Encoder $encoder,
                                Repository $config)
    {
        $this->defaultBuilder = $config->get('jwt.builder', 'default');
        $this->builderConfigs = $config->get('jwt.builders', []);

        $this
            ->setDefaultExpiresIn($config->get('jwt.builder.default_expires_in', '10 minutes'))
            ->setBuilderClass($config->get('jwt.builder.class', Builder::class));
    }

    public function getSignerRegistry(): SignerRegistry
    {
        return $this->signerRegistry;
    }

    public function setSignerRegistry(SignerRegistry $signerRegistry): static
    {
        $this->signerRegistry = $signerRegistry;
        return $this;
    }

    public function getKeySetResolver(): KeySetResolver
    {
        return $this->keySetResolver;
    }

    public function setKeySetResolver(KeySetResolver $keySetResolver): static
    {
        $this->keySetResolver = $keySetResolver;
        return $this;
    }

    public function getClock(): ClockInterface
    {
        return $this->clock;
    }

    public function setClock(ClockInterface $clock): static
    {
        $this->clock = $clock;
        return $this;
    }

    public function getEncoder(): Encoder
    {
        return $this->encoder;
    }

    public function setEncoder(Encoder $encoder): static
    {
        $this->encoder = $encoder;
        return $this;
    }

    public function setDefaultExpiresIn(DateInterval|string|int|null $defaultExpiresIn): static
    {
        if(is_null($defaultExpiresIn)) {
            $this->defaultExpiresIn = null;
        } elseif(is_numeric($defaultExpiresIn)) {
            $this->defaultExpiresIn = CarbonInterval::seconds(intval($defaultExpiresIn));
        } elseif(is_string($defaultExpiresIn)) {
            $this->defaultExpiresIn = CarbonInterval::make($defaultExpiresIn);
        } else {
            $this->defaultExpiresIn = $defaultExpiresIn;
        }
        return $this;
    }

    public function setBuilderClass(string $className): static
    {
        if($className !== Builder::class && !is_subclass_of($className, Builder::class)) {
            throw new InvalidArgumentException("$className is not a subclass of ".Builder::class);
        }

        $this->builderClass = $className;
        return $this;
    }

    public function getBuilderConfig(?string $builder = null): array
    {
        $builder ??= $this->defaultBuilder;
        return $this->builderConfigs[$builder] ?? [];
    }

    public function builder(?string $builder = null): Builder
    {
        $builder ??= $this->defaultBuilder;
        $config = $this->getBuilderConfig($builder);

        $className = $config['class'] ?? Builder::class;
        if($className !== Builder::class && !is_subclass_of($className, Builder::class)) {
            throw new InvalidArgumentException(
                "$className is not a subclass of ".Builder::class." (Review the 'class' property of the config for jwt builder '$builder'!)"
            );
        }

        $defaultExpiresIn = $config['expires_in'] ?? null;
        if(!is_null($defaultExpiresIn)) {
            if(is_numeric($defaultExpiresIn)) $defaultExpiresIn = CarbonInterval::seconds(intval($defaultExpiresIn));
            elseif(is_string($defaultExpiresIn)) $defaultExpiresIn = CarbonInterval::make($defaultExpiresIn);
            assert($defaultExpiresIn instanceof DateInterval);
        }

        $claims = $config['claims'] ?? [];

        $audience = $config['audience'] ?? $config['audiences'] ?? null;
        if(!empty($audience)) $claims['aud'] = $audience;

        $issuer = $config['issuer'] ?? null;
        if(is_string($issuer) && !empty($issuer)) $claims['iss'] = $issuer;

        $subject = $config['subject'] ?? null;
        if(is_string($subject) && !empty($subject)) $claims['sub'] = $subject;

        $headers = $config['headers'] ?? [];

        $signer = $this->signerRegistry->signer($config['signer'] ?? null);

        return ($className)::create(
            signerRegistry: $this->getSignerRegistry(),
            keySetResolver: $this->getKeySetResolver(),
            encoder: $this->getEncoder(),
            clock: $this->getClock(),
            defaultExpiresIn: $defaultExpiresIn,
            signer: $signer,
            headers: $headers,
            claims: $claims
        );
    }
}
