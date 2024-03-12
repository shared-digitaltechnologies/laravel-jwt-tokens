<?php

use Illuminate\Foundation\Application;

use function Orchestra\Testbench\default_skeleton_path;

return Application::configure($APP_BASE_PATH ?? default_skeleton_path())
    ->withProviders()
    ->withRouting(
        web: __DIR__.'/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: __DIR__.'/up'
    );
