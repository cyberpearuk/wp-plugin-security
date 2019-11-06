<?php declare(strict_types=1);
return [
    "strict-type-checking" => true,
    "strict_method_checking" => true,
    "strict_object_checking" => true,
    "strict_param_checking" => true,
    "strict_property_checking" => true,
    "strict_return_checking" => true,
    "analyze_signature_compatibility" => true,
    'suppress_issue_types' => [
        "PhanUnreferencedUseNormal", // Doesn't work with @var
        "PhanUndeclaredInterface", // Doesn't work correctly with using inteface from vendor
    ],
    "target_php_version" => '7.1',
    'file_list' => [
        'wp-plugin-security.php',
        'vendor/wordpress/wordpress/wp-includes/plugin.php',
        'vendor/wordpress/wordpress/wp-includes/cache.php',
        'vendor/wordpress/wordpress/wp-includes/class-phpass.php',
        'vendor/wordpress/wordpress/wp-load.php'
    ],
    'directory_list' => [
        'src',
    ],
    "exclude_analysis_directory_list" => [
        'vendor'
    ],
    'plugins' => [
        'AlwaysReturnPlugin',
        'UnreachableCodePlugin',
        'DollarDollarPlugin',
        'DuplicateArrayKeyPlugin',
        'PregRegexCheckerPlugin',
        'PrintfCheckerPlugin',
    ],
];
