<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use Illuminate\Contracts\Filesystem\Factory as FilesystemFactory;
use Shrd\Laravel\JwtTokens\Contracts\KeySetLoader;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

class DiskLoader extends PrefixKeySetLoader
{
    public function __construct(protected FilesystemFactory $filesystemFactory,
                                protected KeySetLoader $defaultLoader,
                                string $prefix)
    {
        parent::__construct($prefix);
    }

    public function loadKeySet(string $descriptor, array $config): KeySet
    {
        $reference = $this->removeDescriptorPrefix($descriptor);

        $parts = explode(':', $reference, 2);
        if(count($parts) <= 1) {
            $disk = null;
            $path = $reference;
        } else {
            $disk = $parts[0];
            if(strlen($disk) === 0) $disk = null;
            $path = $reference;
        }

        $disk ??= $config['disk'] ?? null;

        $contents = $this->filesystemFactory->disk($disk)->get($path);

        return $this->defaultLoader->loadKeySet($contents, $config);
    }
}
