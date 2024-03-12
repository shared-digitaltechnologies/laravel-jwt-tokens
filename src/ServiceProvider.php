<?php

namespace Shrd\Laravel\JwtTokens;

use Carbon\FactoryImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use Illuminate\Support\ServiceProvider as BaseServiceProvider;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Shrd\Laravel\JwtTokens\Guards\JwtTokenGuard;
use Shrd\Laravel\JwtTokens\Tokens\Parser;
use Shrd\Laravel\JwtTokens\UserProviders\DefaultTokenUserProviderFactory;

class ServiceProvider extends BaseServiceProvider
{

    public function register(): void
    {
        $this->app->singleton(JoseEncoder::class);
        $this->app->bind(Decoder::class, JoseEncoder::class);
        $this->app->bind(Encoder::class, JoseEncoder::class);

        $this->app->singleton(Parser::class);
        $this->app->bind(ParserInterface::class, Parser::class);


        $this->app->singleton(DefaultTokenUserProviderFactory::class);
        $this->app->bind(
            Contracts\TokenUserProviderFactory::class,
            DefaultTokenUserProviderFactory::class
        );

        $this->app->singleton(JwtService::class, function(Application $app) {
            return new JwtService(
                container: $app,
                config: $app['config'],
                cache: $app['cache'],
                validationFactory: $app[ValidationFactory::class],
                encoder: $app[Encoder::class],
                parser: $app[ParserInterface::class],
            );
        });

        $this->app->bind(
            Contracts\TokenValidatorFactory::class,
            JwtService::class
        );

        $this->app->bind(Contracts\KeySetLoader::class, Contracts\KeySetLoaderFactory::class);
        $this->app->bind(
            Contracts\KeySetLoaderFactory::class,
            fn(Application $app) => $app->make(JwtService::class)->keySetLoaders()
        );

        $this->app->bind(
            Contracts\KeySetResolver::class,
            fn(Application $app) => $app->make(JwtService::class)->keySets()
        );

        $this->app->bind(
            Contracts\ConstraintFactory::class,
            fn(Application $app) => $app->make(JwtService::class)->constraints()
        );

        $this->app->bind(
            Contracts\SignerRegistry::class,
            fn(Application $app) => $app->make(JwtService::class)->signers()
        );

        $this->app->bind(
            Contracts\TokenBuilderFactory::class,
            fn(Application $app) => $app->make(JwtService::class)->builders()
        );

    }

    public function boot(AuthManager $authManager): void
    {
        $this->bootPackage();
        $this->bootAuthManager($authManager);
    }

    private function bootPackage(): void
    {
        $this->publishes([
            __DIR__.'/../config/jwt.php' => config_path('jwt.php')
        ]);
    }

    private function bootAuthManager(AuthManager $authManager): void
    {
        $authManager->extend('jwt-bearer-token', static function (Application $app, string $name, array $config) {

            $providerKey = $config['provider'];
            $provider = $app[DefaultTokenUserProviderFactory::class]->createTokenUserProvider($providerKey);
            $parser = $app[ParserInterface::class];

            $guard = new JwtTokenGuard(
                name: $name,
                parser: $parser,
                provider: $provider,
            );

            return $guard
                ->setDispatcher($app['events'])
                ->setRequest($app->refresh('request', $guard, 'setRequest'));
        });
    }
}
