<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Filesystem\Factory as FilesystemFactory;
use Illuminate\Http\Client\Factory as ClientFactory;
use Illuminate\Support\Str;
use IteratorAggregate;
use Shrd\EncodingCombinators\Strings\ConstantTime\Encoding;
use Shrd\Laravel\JwtTokens\Contracts\KeySetLoader;
use Shrd\Laravel\JwtTokens\Contracts\KeySetLoaderFactory;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

/**
 * @implements IteratorAggregate<string, KeySetLoader>
 */
class KeySetLoaderManager implements KeySetLoaderFactory
{
    /**
     * @var array<string, Closure(Container $app, KeySetLoader $defaultLoader): KeySetLoader>
     */
    protected array $customConstructors = [];

    protected array $loaders = [];

    public function __construct(protected Container $container)
    {
    }

    /**
     * @return Container
     */
    public function getContainer(): Container
    {
        return $this->container;
    }

    /**
     * @param Container $container
     * @return $this
     */
    public function setContainer(Container $container): static
    {
        $this->container = $container;
        return $this;
    }

    public function extend(string $prefix, callable $callback): static
    {
        $this->customConstructors[$prefix] = $callback(...);
        unset($this->loaders[$prefix]);
        return $this;
    }

    protected function callCustomConstructor(string $prefix): KeySetLoader
    {
        return $this->customConstructors[$prefix]($this->container, $this->defaultLoader());
    }

    public function loaderFor(string $descriptor): KeySetLoader
    {
        $parts = explode(':', $descriptor,2);
        if(count($parts) <= 1) {
            if(Str::lower($descriptor) === 'none') return $this->createNoneLoader();

            return $this->defaultLoader();
        } else {
            return $this->loaderByPrefix($parts[0]);
        }
    }

    public function loadKeySet(string $descriptor, array $config): KeySet
    {
        return $this->loaderFor($descriptor)->loadKeySet($descriptor, $config);
    }

    protected function loaderByPrefix(string $prefix): KeySetLoader
    {
        if(array_key_exists($prefix, $this->loaders)) {
            return $this->loaders[$prefix];
        }


        $loader = $this->createLoader($prefix);

        if($loader !== null) {
            $this->loaders[$prefix] = $loader;
            return $loader;
        }

        return $this->defaultLoader();
    }

    protected function defaultLoader(): KeySetLoader
    {
        return new AsymmetricKeyLoader;
    }

    protected function createLoader(string $prefix): ?KeySetLoader
    {
        if(array_key_exists($prefix, $this->customConstructors)) {
            return $this->callCustomConstructor($prefix);
        }


        $method = 'create'.Str::studly($prefix).'Loader';
        if(method_exists($this, $method)) {
            return $this->$method();
        }

        return null;
    }

    protected function createFileLoader(): FileLoader
    {
        return new FileLoader(
            defaultLoader: $this->defaultLoader(),
            prefix: 'file'
        );
    }

    protected function createHttpLoader(): HttpLoader
    {
        return new HttpLoader(
            http: $this->container->make(ClientFactory::class)
        );
    }

    protected function createHttpsLoader(): HttpLoader
    {
        return $this->createHttpLoader();
    }

    protected function createDiskLoader(): DiskLoader
    {
        return new DiskLoader(
            filesystemFactory: $this->container->make(FilesystemFactory::class),
            defaultLoader: $this->defaultLoader(),
            prefix: 'disk'
        );
    }

    protected function createNoneLoader(): NoneLoader
    {
        return new NoneLoader(
            prefix: 'none'
        );
    }

    protected function createPlainLoader(): SecretLoader
    {
        return new SecretLoader(Encoding::Plain, 'plain');
    }

    protected function createHexLoader(): SecretLoader
    {
        return new SecretLoader(Encoding::Hex, 'hex');
    }

    protected function createBase64Loader(): SecretLoader
    {
        return new SecretLoader(Encoding::Base64, 'base64');
    }

    protected function createBase64UrlLoader(): SecretLoader
    {
        return new SecretLoader(Encoding::Base64UrlNoPadding, 'base64url');
    }
}
