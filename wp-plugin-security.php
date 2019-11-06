<?php declare(strict_types=1);
/**
 * Copyright (C) 2019 CyberPear (https://www.cyberpear.co.uk) - All Rights Reserved
 *
 * Plugin Name: WP Security Plugin
 * Description: Replaces WordPress password functions with native PHP password functions.
 *
 * phpcs:disable SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingReturnTypeHint
 * phpcs:disable Generic.NamingConventions.CamelCapsFunctionName.NotCamelCaps
 * phpcs:disable SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingParameterTypeHint
 */
defined('ABSPATH') or die('Access denied');

use CyberPear\WpThemeSecurity\PHPPasswordHashingFeature;

require_once __DIR__ . '/src/WPPasswordHashingFeature.php';
require_once __DIR__ . '/src/PHPPasswordHashingFeature.php';

if (function_exists('wp_hash_password') 
        || function_exists('wp_check_password')
        || function_exists('wp_set_password')) {
    
    error_log('Password functions already defined.');
}
if (!function_exists('wp_hash_password')) {

    function wp_hash_password(string $password) {
        return PHPPasswordHashingFeature::getInstance()->hashPassword($password);
    }

}

if (!function_exists('wp_check_password')) {

    function wp_check_password(string $password, string $hash, $userId = ''): bool {
        if (empty($userId)) {
            throw new Exception("Missing user ID");
        }

        $userId = intval($userId);
        return PHPPasswordHashingFeature::getInstance()->passwordCheck($password, $hash, $userId);
    }

}

if (!function_exists('wp_set_password')) {

    function wp_set_password(string $password, $userId = '') {
        if (empty($userId)) {
            throw new Exception("Missing user ID");
        }

        $userId = intval($userId);
        return PHPPasswordHashingFeature::getInstance()->setPassword($password, $userId);
    }

}
