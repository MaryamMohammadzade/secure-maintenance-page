<?php
/**
 * Plugin Name:       Secure Maintenance Page
 * Description:       Security-focused maintenance mode: show your own uploaded HTML page or one of the built-in Persian/English templates.
 * Version:           1.1.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Sisoog
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       secure-maintenance-page
 * Domain Path:       /languages
 */

defined( 'ABSPATH' ) || exit;

define( 'SMP_VERSION', '1.1.0' );
define( 'SMP_FILE', __FILE__ );
define( 'SMP_DIR', plugin_dir_path( __FILE__ ) );

require_once SMP_DIR . 'includes/class-smp-sanitizer.php';
require_once SMP_DIR . 'includes/class-smp-plugin.php';
require_once SMP_DIR . 'includes/class-smp-admin.php';
require_once SMP_DIR . 'includes/class-smp-frontend.php';

register_activation_hook( __FILE__, array( 'SMP_Plugin', 'activate' ) );

add_action(
	'plugins_loaded',
	static function () {
		load_plugin_textdomain( 'secure-maintenance-page', false, dirname( plugin_basename( SMP_FILE ) ) . '/languages' );
		SMP_Frontend::init();
		if ( is_admin() ) {
			SMP_Admin::init();
		}
		SMP_Admin::init_global();
	}
);
