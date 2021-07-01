<?php declare(strict_types=1);
/**
 * Copyright (C) 2019 CyberPear (https://www.cyberpear.co.uk) - All Rights Reserved
 *
 * Plugin Name: WP Security Plugin
 * Description: Replaces WordPress password functions with native PHP password functions.
 * Version: $_VERSION
 *
 * phpcs:disable SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingReturnTypeHint
 * phpcs:disable Generic.NamingConventions.CamelCapsFunctionName.NotCamelCaps
 * phpcs:disable SlevomatCodingStandard.TypeHints.TypeHintDeclaration.MissingParameterTypeHint
 */
defined('ABSPATH') or die('Access denied');

use CyberPear\WpThemeSecurity\PHPPasswordHashingFeature;
use CyberPear\WpThemeSecurity\WpPluginSecurityException;

require_once __DIR__ . '/src/WpPluginSecurityException.php';
require_once __DIR__ . '/src/WPPasswordHashingFeature.php';
require_once __DIR__ . '/src/PHPPasswordHashingFeature.php';

if (function_exists('wp_hash_password') ||
        function_exists('wp_check_password') ||
        function_exists('wp_set_password')) {
    add_action('admin_notices', function (): void {
        ?>
        <div class="notice notice-error">

            <h2>Important WP Plugin Security Notice</h2>
            <p>
                A password function is already defined. WP Plugin Security won&apos;t
                be able to work properly, either resolve the issue (e.g. by removing the conflicting plugin)
                or by removing the WP Plugin Security.
            </p>
        </div>
        <?php
    });
} else {

    /**
     *
     * @param string $password
     *
     * @return string
     */
    function wp_hash_password(string $password): string {
        return PHPPasswordHashingFeature::getInstance()->hashPassword($password);
    }

    /**
     *
     * @param string $password
     * @param string $hash
     * @param string|int $userId
     *
     * @return bool
     */
    function wp_check_password(string $password, string $hash, $userId = ''): bool {
        if (empty($userId)) {
            throw new WpPluginSecurityException("Missing user ID");
        }

        $userId = intval($userId);
        return PHPPasswordHashingFeature::getInstance()->passwordCheck($password, $hash, $userId);
    }

    /**
     *
     * @param string $password
     * @param string|int $userId
     * @return bool
     */
    function wp_set_password(string $password, $userId = ''): bool {
        if (empty($userId)) {
            throw new WpPluginSecurityException("Missing user ID");
        }

        $userId = intval($userId);
        return PHPPasswordHashingFeature::getInstance()->setPassword($password, $userId);
    }

}
