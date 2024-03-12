<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use Shrd\Laravel\JwtTokens\Contracts\KeySetLoader;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

class FileLoader extends PrefixKeySetLoader
{
    public function __construct(protected KeySetLoader $defaultLoader, string $prefix)
    {
        parent::__construct($prefix);
    }

    public function loadKeySet(string $descriptor, array $config): KeySet
    {
        $contents = file_get_contents(
            filename: $config['filename'] ?? $this->removeDescriptorPrefix($descriptor),
            use_include_path: $config['use_include_path'] ?? null,
            context: $config['context'] ?? null,
            offset: $config['offset'] ?? null,
            length: $config['length'] ?? null
        );

        return $this->defaultLoader->loadKeySet($contents, $config);
    }
}
