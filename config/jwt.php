<?php

return [

    /* ------------------------------------------------------------------
     *  CONSTRAINTS
     * ------------------------------------------------------------------
     *
     * The following configuration values concern the default values
     * for the token constraints used when checking the tokens.
     *
     */

    "constraints" => [

        // The allowed leeway to compensate for clock drift between services.
        "leeway"   => env('JWT_LEEWAY', '10 seconds'),

        // The default audience value of this application.
        "audience" => env('JWT_DEFAULT_AUDIENCE'),

        // The default allowed issuers for which tokens are accepted.
        "issuers"  => [
            env('JWT_ISSUER')
        ],

        // The default list of allowed algorithms.
        "algorithms" => [
            env('JWT_ALGORITHMS', "RS256,RS384,RS512"),
            "HS256,HS384,HS512" => env('JWT_ALGORITHM_ALLOW_SYMMETRIC', false),
            "none" => env('JWT_ALGORITHM_ALLOW_NONE', env('APP_ENV') === 'local')
        ],
    ],

    /* ------------------------------------------------------------------
     *  KEYS and KEY SETS
     * ------------------------------------------------------------------
     *
     * Configures how the application behaves around the cryptographic
     * keys used to sign/verify jwt tokens.
     *
     */

    "keys" => [

        // Configures how the public keys should be cached.
        "cache" => [
            "enabled" => env('JWT_KEYS_CACHE_ENABLED', true),
            "store"   => env('JWT_KEYS_CACHE_STORE'),
            "ttl"     => env('JWT_KEYS_CACHE_TTL', '1 day'),
            "prefix"  => env('JWT_KEYS_CACHE_PREFIX', 'jwt:key_sets:'),
        ],

        // Optional extra configuration for each KeySet descriptor
        "sets" => [
        ]
    ],

    /* ------------------------------------------------------------------
     *  SIGNERS
     * ------------------------------------------------------------------
     *
     * Configures the token signers that this application can use to
     * sign JWT tokens.
     *
     */

    // The name of the signer that is used by default.
    "signer" => env('JWT_SIGNER', 'default'),


    // The configuration of the signers of the application.
    "signers" => [

        // The default signer, which uses the app key and a symmetric
        // algorithm to sign the tokens.
        "default" => [
            "driver" => "algorithm",
            "algorithm" => "HS256",
            "key" => env('APP_KEY')
        ],

        // The none driver, which produces only empty signatures for jwt
        // tokens. This is VERY insecure for use in production, but might
        // be useful during local testing.
        "none" => [
            "driver" => "none"
        ]
    ],


    /* ------------------------------------------------------------------
     *  TOKEN BUILDER PRESETS
     * ------------------------------------------------------------------
     *
     * Configures the token builder presets of this application.
     *
     */

    // The name of the default token builder preset.
    "builder" => env('JWT_BUILDER', 'default'),

    // The configuration for the token builder presets.
    "builders" => [
        "default" => [
            "expires_in" => "10 minutes",
            "signer" => "default"
        ]
    ],



];
