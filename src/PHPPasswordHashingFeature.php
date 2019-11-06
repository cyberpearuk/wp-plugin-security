<?php declare(strict_types=1);
/**
 * Copyright (C) 2019 CyberPear (https://www.cyberpear.co.uk) - All Rights Reserved
 */

namespace CyberPear\WpThemeSecurity;

/**
 * PHPPasswordHashingFeature
 *
 * @author jbuncle
 */
class PHPPasswordHashingFeature extends WPPasswordHashingFeature {

    public function hashPassword(string $plainTextPassword): string {
        // Hook to allow options to be defined by other plugins/themes
        $algo = apply_filters('wp_password_hash_algo', PASSWORD_DEFAULT);
        $options = apply_filters('wp_password_hash_options', array());

        if (!is_int($algo)) {
            throw new WpPluginSecurityException("Bad algorithm provided");
        }

        if (!is_array($options) && $options !== null) {
            throw new WpPluginSecurityException("Bad options provided");
        }

        if (is_array($options)) {
            $this->validatePasswordOptions($algo, $options);
            $hash = \password_hash($plainTextPassword, $algo, $options);
        } else {
            $hash = \password_hash($plainTextPassword, $algo);
        }

        if ($hash === false || $hash === null) {
            throw new WpPluginSecurityException("Failed to generate password hash");
        }

        return $hash;
    }

    /**
     *
     * @param int $algo
     * @param array<string,mixed> $options
     *
     * @return void
     */
    private function validatePasswordOptions(int $algo, array $options): void {
        // Also check against DEFAULT as although it's currently the same
        // there's a higher chance of a future algorithm having the same options
        if ($algo === PASSWORD_BCRYPT || $algo === PASSWORD_DEFAULT) {
            $this->validateBcryptOptions($options);
            return;
        }

        if ($algo === PASSWORD_ARGON2I) {
            $this->validateArgon2Options($options);
            return;
        }

        throw new WpPluginSecurityException("Unexpected algorithm $algo");
    }

    /**
     *
     * @param array<string,mixed> $options
     *
     * @return void
     */
    private function validateBcryptOptions(array $options): void {
        foreach ($options as $key => $value) {
            if (!in_array($value, ['cost'])) {
                throw new WpPluginSecurityException("Bad options");
            }

            if (strcasecmp($key, 'cost') && !is_int($value)) {
                throw new WpPluginSecurityException("Bad cost");
            }
        }
    }

    /**
     *
     * @param array<string,mixed> $options
     *
     * @return void
     */
    private function validateArgon2Options(array $options): void {
        foreach ($options as $key => $value) {
            if (!in_array($value, ['memory_cost', 'time_cost', 'threads'])) {
                throw new WpPluginSecurityException("Bad options");
            }

            if (strcasecmp($key, 'memory_cost') && !is_int($value)) {
                throw new WpPluginSecurityException("Bad memory_cost");
            }

            if (strcasecmp($key, 'time_cost') && !is_int($value)) {
                throw new WpPluginSecurityException("Bad time_cost");
            }

            if (strcasecmp($key, 'threads') && !is_int($value)) {
                throw new WpPluginSecurityException("Bad threads");
            }
        }
    }

    protected function doPasswordCheck(string $password, string $hash): bool {
        $info = \password_get_info($hash);
        if (!empty($info['algo'])) {
            return \password_verify($password, $hash);
        }

        // Algorithm not defined as part of password, do legacy check
        return parent::doPasswordCheck($password, $hash);
    }

    protected function requiresRehash(string $hash): bool {
        if (parent::requiresRehash($hash)) {
            return true;
        }

        // Not already rehashing
        return \password_needs_rehash($hash, PASSWORD_DEFAULT);
    }

}
