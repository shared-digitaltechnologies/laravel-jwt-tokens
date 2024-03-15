<?php

namespace Shrd\Laravel\JwtTokens;

use Carbon\FactoryImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider as BaseServiceProvider;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Psr\Clock\ClockInterface;
use Shrd\Laravel\JwtTokens\Guards\JwtTokenGuard;
use Shrd\Laravel\JwtTokens\Keys\Loaders\KeySetLoaderManager;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySetManager;
use Shrd\Laravel\JwtTokens\Loaders\TokenLoaderManager;
use Shrd\Laravel\JwtTokens\Signers\Signer;
use Shrd\Laravel\JwtTokens\Signers\SignerManager;
use Shrd\Laravel\JwtTokens\Signers\Verifier;
use Shrd\Laravel\JwtTokens\Tokens\BuilderFactory;
use Shrd\Laravel\JwtTokens\Tokens\Parser;
use Shrd\Laravel\JwtTokens\Console\Commands;
use Shrd\Laravel\JwtTokens\Validation\Constraints\ConstraintManager;

class ServiceProvider extends BaseServiceProvider
{

    public function register(): void
    {
        $this->app->singletonIf(ClockInterface::class, FactoryImmutable::class);

        // Encoders
        $this->app->singleton(JoseEncoder::class);
        $this->app->bind(Decoder::class, JoseEncoder::class);
        $this->app->bind(Encoder::class, JoseEncoder::class);

        // Parsers
        $this->app->singleton(Parser::class);
        $this->app->bind(ParserInterface::class, Parser::class);

        // Key Sets
        $this->app->singleton(KeySetLoaderManager::class);
        $this->app->bind(Contracts\KeySetLoaderFactory::class, KeySetLoaderManager::class);
        $this->app->bind(Contracts\KeySetLoader::class, Contracts\KeySetLoaderFactory::class);

        $this->app->singleton(KeySetManager::class);
        $this->app->bind(Contracts\KeySetResolver::class, KeySetManager::class);

        // Token validation and loaders
        $this->app->singleton(ConstraintManager::class);
        $this->app->bind(Contracts\ConstraintFactory::class, ConstraintManager::class);
        $this->app->bind(Contracts\TokenValidatorBuilderFactory::class, ConstraintManager::class);

        $this->app->singleton(TokenLoaderManager::class);
        $this->app->bind(Contracts\TokenLoaderRegistry::class, TokenLoaderManager::class);

        $this->app->bind(Contracts\TokenLoader::class, function(Application $app, array $config = []) {
            return $app->make(Contracts\TokenLoaderRegistry::class)->get($config['name'] ?? null);
        });
        $this->app->bind(Contracts\TokenValidator::class, Contracts\TokenLoader::class);

        // Token signers/builders
        $this->app->singleton(SignerManager::class);
        $this->app->bind(Contracts\SignerRegistry::class, SignerManager::class);
        $this->app->bind(Signer::class, function(Application $app, array $config = []) {
            $algorithm = $config['algorithm'] ?? $config['alg'] ?? null;
            if($algorithm !== null) {
                return $app->make(Contracts\SignerRegistry::class)->signerUsing(
                    algorithm: $algorithm,
                    key: $config['key'],
                    kid: $config['kid'] ?? null
                );
            } else {
                return $app->make(Contracts\SignerRegistry::class)->signer($config['name'] ?? null);
            }
        });

        $this->app->bind(Verifier::class, function(Application $app, array $config = []) {
            $algorithm = $config['algorithm'] ?? $config['alg'] ?? null;
            if($algorithm !== null) {
                return $app->make(Contracts\SignerRegistry::class)->verifierUsing(
                    algorithm: $algorithm,
                    key: $config['key'],
                );
            } else {
                return $app->make(Contracts\SignerRegistry::class)->verifier($config['name'] ?? null);
            }
        });

        $this->app->singleton(BuilderFactory::class);
        $this->app->bind(Contracts\TokenBuilderFactory::class, BuilderFactory::class);

        // JWT Service Facade
        $this->app->singleton(JwtService::class);
    }

    public function boot(AuthManager $authManager): void
    {
        $this->bootPackage();
        $this->bootAuthManager($authManager);

        if($this->app->runningInConsole()) {
            $this->bootConsole();
        }
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

            $providerKey = $config['provider'] ?? null;

            $auth = $app->make('auth');
            assert($auth instanceof AuthFactory);
            $provider = $auth->createUserProvider($providerKey);

            $tokenLoaderName = $config['token_loader'] ?? null;
            $loaderRegistry = $app->make(Contracts\TokenLoaderRegistry::class);
            $loader = $loaderRegistry->get($tokenLoaderName);

            $guard = new JwtTokenGuard(
                name: $name,
                loader: $loader,
                provider: $provider,
            );

            return $guard
                ->setRequest($app->refresh('request', $guard, 'setRequest'));
        });
    }

    private function bootConsole(): void
    {
        $this->commands(
            Commands\IdeHelper::class
        );
    }
}
