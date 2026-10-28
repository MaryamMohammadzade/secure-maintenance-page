<?php
/**
 * Front-end: shows the maintenance page to visitors.
 */

defined( 'ABSPATH' ) || exit;

final class SMP_Frontend {

	public static function init() {
		// Priority 0 so we run before themes/plugins redirect or output anything.
		add_action( 'template_redirect', array( __CLASS__, 'maybe_show' ), 0 );
		// Priority 101: after core's cookie/nonce check (100) so the current user is final.
		add_filter( 'rest_authentication_errors', array( __CLASS__, 'maybe_block_rest' ), 101 );
		add_filter( 'xmlrpc_enabled', array( __CLASS__, 'maybe_disable_xmlrpc' ) );
	}

	public static function maybe_show() {
		if ( ! SMP_Plugin::is_enabled() || SMP_Plugin::user_can_bypass() ) {
			return;
		}
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		$s = SMP_Plugin::settings();
		SMP_Plugin::render( $s['template'], true );
	}

	public static function maybe_block_rest( $result ) {
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		$s = SMP_Plugin::settings();
		if ( empty( $s['enabled'] ) || empty( $s['block_rest'] ) || SMP_Plugin::user_can_bypass() ) {
			return $result;
		}
		return new WP_Error(
			'smp_maintenance',
			__( 'The site is under maintenance.', 'secure-maintenance-page' ),
			array( 'status' => 503 )
		);
	}

	public static function maybe_disable_xmlrpc( $enabled ) {
		$s = SMP_Plugin::settings();
		if ( ! empty( $s['enabled'] ) && ! empty( $s['block_rest'] ) ) {
			return false;
		}
		return $enabled;
	}
}
