<?php declare(strict_types=1);
/**
 * Copyright (C) 2019 CyberPear (https://www.cyberpear.co.uk) - All Rights Reserved
 *
 * phpcs:disable SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingReturnTypeHint
 * phpcs:disable Generic.NamingConventions.CamelCapsFunctionName.NotCamelCaps
 * phpcs:disable SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingParameterTypeHint
 */
require_once __DIR__ . '/../vendor/autoload.php';

use CyberPear\WpThemeSecurity\PHPPasswordHashingFeature;

if (\function_exists("wp_hash_password")) {
    throw new Exception("Password function 'wp_hash_password' already setup");
}

if (\function_exists("wp_check_password")) {
    throw new Exception("Password function 'wp_check_password' already setup");
}

if (\function_exists("wp_set_password")) {
    throw new Exception("Password function 'wp_set_password' already setup");
}

function wp_hash_password(string $password) {
    return PHPPasswordHashingFeature::getInstance()->hashPassword($password);
}

function wp_check_password(string $password, string $hash, $userId = ''): bool {
    if (empty($userId)) {
        throw new Exception("Missing user ID");
    }

    $userId = intval($userId);
    return PHPPasswordHashingFeature::getInstance()->passwordCheck($password, $hash, $userId);
}

function wp_set_password(string $password, $userId = '') {
    if (empty($userId)) {
        throw new Exception("Missing user ID");
    }

    $userId = intval($userId);
    return PHPPasswordHashingFeature::getInstance()->setPassword($password, $userId);
}
