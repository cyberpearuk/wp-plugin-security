<?php declare(strict_types=1);
/**
 * Copyright (C) 2019 CyberPear (https://www.cyberpear.co.uk) - All Rights Reserved
 */

namespace CyberPear\WpThemeSecurity;

use Exception;

/**
 * PHPPasswordHashingFeature
 *
 * @author jbuncle
 */
class PHPPasswordHashingFeature extends WPPasswordHashingFeature {

    public function hashPassword(string $plainTextPassword): string {
        // Hook to allow options to be defined by other plugins/themes
        $options = apply_filters('wp_password_hash_options', array());
        $hash = \password_hash($plainTextPassword, PASSWORD_DEFAULT, $options);
        if ($hash === false || $hash === null) {
            throw new Exception("Failed to generate password hash");
        }

        return $hash;
    }

    protected function doPasswordCheck(string $password, string $hash): bool {
        $info = \password_get_info($hash);
        if (!empty($info['algo'])) {
            return \password_verify($password, $hash);
        }

        return parent::doPasswordCheck($password, $hash);
    }

    protected function requiresRehash(string $hash): bool {
        if (parent::requiresRehash($hash) !== true) {
            // Not already rehashing
            return \password_needs_rehash($hash, PASSWORD_DEFAULT);
        }

        return true;
    }

}
