<?php
/**
 * Removes all plugin data when the plugin is deleted from the dashboard.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

foreach ( array( 'smp_settings', 'smp_custom_html', 'smp_custom_meta' ) as $smp_option ) {
	delete_option( $smp_option );
}
