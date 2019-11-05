<?php declare(strict_types=1);
defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

/**
 * Plugin Name: WP Security Plugin
 * Description: Currently only includes the use of native PHP password functions.
 */

require_once './src/PHPPasswordHashingFeature.php';
require_once './src/WPPasswordHashingFeature.php';
require_once './src/setup-functions.php';
