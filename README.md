# WP Security Plugin

Replaces WordPress password functions with native PHP password functions.

## WP Filters

| Hook                     | Description                         |
| ------------------------ | ----------------------------------- |
| wp_password_hash_algo    | Filter the algorithm that is provided to the [password_hash](https://www.php.net/manual/en/function.password-hash.php) function |
| wp_password_hash_options | Filter the options array that is provided to the [password_hash](https://www.php.net/manual/en/function.password-hash.php) function |