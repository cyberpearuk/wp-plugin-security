<?php declare(strict_types=1);
/**
 * Copyright (C) 2019 CyberPear (https://www.cyberpear.co.uk) - All Rights Reserved
 */

namespace CyberPear\WpThemeSecurity;

use PasswordHash;
use function wp_hash_password;
use function wp_set_password;

/**
 * WPPasswordHashingFeature - Recreates core WP password functionality.
 *
 * @author jbuncle
 */
class WPPasswordHashingFeature {

    /**
     *
     * @var WPPasswordHashingFeature
     */
    private static $instance;

    public static function getInstance(): self {
        if (!isset(self::$instance)) {
            return new static();
        }

        return self::$instance;
    }

    public function passwordCheck(
            string $password,
            string $hash,
            int $userId
    ): bool {
        $check = $this->doPasswordCheck($password, $hash);

        if ($check && $userId) {
            if (\apply_filters('wp_check_rehash_password', false, $hash)) {
                // Set new password hash using plain text password
                wp_set_password($password, $userId);
                // Redo hash to update the one we're dealing with
                $hash = wp_hash_password($password);
            }
        }

        /** This filter is documented in wp-includes/pluggable.php */
        return apply_filters('check_password', $check, $password, $hash, $userId);
    }

    public function hashPassword(string $password): string {
        global $wp_hasher;

        if (empty($wp_hasher)) {
            include_once ABSPATH . WPINC . '/class-phpass.php';
            // By default, use the portable hash from phpass
            $wp_hasher = new PasswordHash(8, true);
        }

        return $wp_hasher->HashPassword(trim($password));
    }

    protected function requiresRehash(string $hash): bool {
        return $this->looksLikeMd5($hash);
    }

    /**
     * Perform the password check.
     *
     * @global PasswordHash $wp_hasher
     * @param string $password
     * @param string $hash
     * @return bool
     */
    protected function doPasswordCheck(string $password, string $hash): bool {
        // If the hash is still md5...
        if ($this->looksLikeMd5($hash)) {
            return \hash_equals($hash, md5($password));
        }

        global $wp_hasher;
        // If the stored hash is longer than an MD5, presume the
        // new style phpass portable hash.
        if (empty($wp_hasher)) {
            include_once ABSPATH . WPINC . '/class-phpass.php';
            // By default, use the portable hash from phpass
            $wp_hasher = new \PasswordHash(8, true);
        }

        return $wp_hasher->CheckPassword($password, $hash);
    }

    public function setPassword(string $password, int $userId): bool {
        global $wpdb;

        $hash = wp_hash_password($password);
        $wpdb->update(
                $wpdb->users,
                [
                    'user_pass' => $hash,
                    'user_activation_key' => '',
                ],
                [
                    'ID' => $userId
                ]
        );

        /* @phan-suppress-next-line PhanUndeclaredFunction */
        \wp_cache_delete($userId, 'users');

        return true;
    }

    private function looksLikeMd5(string $hash): bool {
        return strlen($hash) === 32;
    }

}
