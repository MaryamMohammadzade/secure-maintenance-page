<?php
/**
 * Shared helpers: settings, templates, page rendering.
 */

defined( 'ABSPATH' ) || exit;

final class SMP_Plugin {

	const OPTION_SETTINGS = 'smp_settings';
	const OPTION_HTML     = 'smp_custom_html';
	const OPTION_META     = 'smp_custom_meta';

	/** Maximum accepted upload size in bytes (filterable). */
	const DEFAULT_MAX_BYTES = 1048576; // 1 MB.

	/**
	 * Allowed template keys. Anything else is rejected.
	 *
	 * @return array<string,string>
	 */
	public static function templates() {
		return array(
			'default-1'    => __( 'Template 1: Light (Persian)', 'secure-maintenance-page' ),
			'default-2'    => __( 'Template 2: Dark (Persian)', 'secure-maintenance-page' ),
			'default-1-en' => __( 'Template 1: Light (English)', 'secure-maintenance-page' ),
			'default-2-en' => __( 'Template 2: Dark (English)', 'secure-maintenance-page' ),
			'custom'       => __( 'Uploaded HTML file', 'secure-maintenance-page' ),
		);
	}

	/**
	 * Template 1 in the site language: Persian for fa_* locales, English otherwise.
	 */
	public static function default_template() {
		return 0 === strpos( get_locale(), 'fa' ) ? 'default-1' : 'default-1-en';
	}

	public static function defaults() {
		return array(
			'enabled'     => 0,
			'template'    => self::default_template(),
			'retry_hours' => 1,
			'block_rest'  => 1,
		);
	}

	public static function activate() {
		add_option( self::OPTION_SETTINGS, self::defaults() );
	}

	public static function settings() {
		$saved = get_option( self::OPTION_SETTINGS, array() );
		return wp_parse_args( is_array( $saved ) ? $saved : array(), self::defaults() );
	}

	public static function is_enabled() {
		$s = self::settings();
		return ! empty( $s['enabled'] );
	}

	public static function max_bytes() {
		return (int) apply_filters( 'smp_max_upload_bytes', self::DEFAULT_MAX_BYTES );
	}

	public static function has_custom_html() {
		$html = get_option( self::OPTION_HTML, '' );
		return is_string( $html ) && '' !== $html;
	}

	/**
	 * Users who can see the real site while maintenance mode is on.
	 */
	public static function user_can_bypass() {
		$cap = apply_filters( 'smp_bypass_capability', 'manage_options' );
		return is_user_logged_in() && current_user_can( $cap );
	}

	/**
	 * Returns the (already sanitized) HTML for the given template key.
	 * Falls back to Template 1 in the site language when the uploaded file is missing.
	 */
	public static function get_html( $template ) {
		if ( ! array_key_exists( $template, self::templates() ) ) {
			$template = self::default_template();
		}

		if ( 'custom' === $template ) {
			if ( self::has_custom_html() ) {
				return self::replace_placeholders( get_option( self::OPTION_HTML ) );
			}
			$template = self::default_template();
		}

		// $template is from a fixed allowlist, so this path cannot be manipulated.
		$path = SMP_DIR . 'templates/' . $template . '.html';
		$html = is_readable( $path ) ? file_get_contents( $path ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( '' === $html ) {
			$html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Maintenance</title></head><body><h1>Maintenance</h1></body></html>';
		}
		return self::replace_placeholders( $html );
	}

	/**
	 * Supported placeholders: {{site_name}}, {{site_description}}, {{year}}.
	 * Values are HTML-escaped.
	 */
	private static function replace_placeholders( $html ) {
		return strtr(
			$html,
			array(
				'{{site_name}}'        => esc_html( get_bloginfo( 'name' ) ),
				'{{site_description}}' => esc_html( get_bloginfo( 'description' ) ),
				'{{year}}'             => esc_html( wp_date( 'Y' ) ),
			)
		);
	}

	/**
	 * Sends the page with hardened headers and stops execution.
	 *
	 * @param string $template    Template key.
	 * @param bool   $maintenance True for real visitors (503), false for admin preview (200).
	 */
	public static function render( $template, $maintenance = true ) {
		$html = self::get_html( $template );

		if ( ! headers_sent() ) {
			if ( $maintenance ) {
				$s = self::settings();
				status_header( 503 );
				header( 'Retry-After: ' . ( max( 1, (int) $s['retry_hours'] ) * HOUR_IN_SECONDS ) );
			} else {
				status_header( 200 );
			}
			nocache_headers();
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'X-Content-Type-Options: nosniff' );
			header( 'X-Frame-Options: DENY' );
			header( 'Referrer-Policy: no-referrer' );
			header( 'X-Robots-Tag: noindex, nofollow' );
			header( 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()' );
			// Second line of defence: even if something slipped through the sanitizer, no script can run.
			header( "Content-Security-Policy: default-src 'none'; script-src 'none'; object-src 'none'; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; media-src 'self' https:; connect-src 'none'; form-action 'none'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'" );
		}

		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'HEAD' === $_SERVER['REQUEST_METHOD'] ) {
			exit;
		}

		// HTML was sanitized by SMP_Sanitizer at upload time (or is a bundled template); CSP above blocks scripts.
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}
}
