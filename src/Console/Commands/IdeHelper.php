<?php

namespace Shrd\Laravel\JwtTokens\Console\Commands;

use Illuminate\Console\Command;
use Shrd\Laravel\JwtTokens\DevHelpers\ConstraintIdeHelperGenerator;

class IdeHelper extends Command
{
    protected $signature = <<<'SIGNATURE'
        jwt:ide-helper {file? : The file to write the stubs to. }
        SIGNATURE;

    protected $description = "Generates an ide-helper file for the jwt library classes.";

    public function handle(ConstraintIdeHelperGenerator $constraintIdeHelperGenerator): int
    {
        $constraintIdeHelper = $constraintIdeHelperGenerator->getHelperFileContents();

        $contents = <<<PHP
            <?php$

            $constraintIdeHelper

            PHP;


        $file = $this->argument('file');
        if($file === null) {
            $this->output->write($contents);
        } else {
            file_put_contents($file, $contents);
            $this->info("Wrote jwt ide-helper file to $file");
        }

        return 0;
    }
}
