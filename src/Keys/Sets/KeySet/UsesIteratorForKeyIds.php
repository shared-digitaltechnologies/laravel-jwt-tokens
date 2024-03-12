<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

use Generator;

trait UsesIteratorForKeyIds
{
    public function keyIds(): Generator
    {
        foreach ($this->getIterator() as $key) {
            $kid = $key->getKeyId();
            if($kid !== null) yield $key;
        }
    }
}
