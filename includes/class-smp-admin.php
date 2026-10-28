<?php
/**
 * Admin: settings page, secure upload, preview, status indicator.
 */

defined( 'ABSPATH' ) || exit;

final class SMP_Admin {

	const CAP  = 'manage_options';
	const SLUG = 'secure-maintenance-page';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
		add_action( 'admin_post_smp_upload', array( __CLASS__, 'handle_upload' ) );
		add_action( 'admin_post_smp_delete', array( __CLASS__, 'handle_delete' ) );
		add_action( 'admin_post_smp_preview', array( __CLASS__, 'handle_preview' ) );
		add_action( 'admin_notices', array( __CLASS__, 'status_notice' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( SMP_FILE ), array( __CLASS__, 'action_links' ) );
	}

	/** Hooks needed on the front end too (admin bar). */
	public static function init_global() {
		add_action( 'admin_bar_menu', array( __CLASS__, 'admin_bar' ), 100 );
	}

	public static function menu() {
		add_options_page(
			__( 'Maintenance Mode', 'secure-maintenance-page' ),
			__( 'Maintenance Mode', 'secure-maintenance-page' ),
			self::CAP,
			self::SLUG,
			array( __CLASS__, 'render_page' )
		);
	}

	public static function action_links( $links ) {
		$url = admin_url( 'options-general.php?page=' . self::SLUG );
		array_unshift( $links, '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Settings', 'secure-maintenance-page' ) . '</a>' );
		return $links;
	}

	public static function register_settings() {
		register_setting(
			'smp_settings_group',
			SMP_Plugin::OPTION_SETTINGS,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( __CLASS__, 'sanitize_settings' ),
				'default'           => SMP_Plugin::defaults(),
				'show_in_rest'      => false,
			)
		);
	}

	public static function sanitize_settings( $input ) {
		// options.php already checked the nonce; re-check capability anyway.
		if ( ! current_user_can( self::CAP ) ) {
			return SMP_Plugin::settings();
		}
		$input = is_array( $input ) ? $input : array();
		$out   = SMP_Plugin::defaults();

		$out['enabled']    = empty( $input['enabled'] ) ? 0 : 1;
		$out['block_rest'] = empty( $input['block_rest'] ) ? 0 : 1;

		$template        = isset( $input['template'] ) ? sanitize_key( $input['template'] ) : SMP_Plugin::default_template();
		$out['template'] = array_key_exists( $template, SMP_Plugin::templates() ) ? $template : SMP_Plugin::default_template();

		$hours              = isset( $input['retry_hours'] ) ? absint( $input['retry_hours'] ) : 1;
		$out['retry_hours'] = min( 168, max( 1, $hours ) );

		return $out;
	}

	/**
	 * Common guard for every admin-post action.
	 */
	private static function guard( $nonce_action ) {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'secure-maintenance-page' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce_action );
	}

	private static function back( $code ) {
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'       => self::SLUG,
					'smp_notice' => $code,
				),
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	public static function handle_upload() {
		self::guard( 'smp_upload' );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated field by field below.
		$file = isset( $_FILES['smp_html_file'] ) && is_array( $_FILES['smp_html_file'] ) ? $_FILES['smp_html_file'] : null;

		if ( ! $file || ! isset( $file['error'], $file['tmp_name'], $file['name'], $file['size'] ) || is_array( $file['error'] ) ) {
			self::back( 'no_file' );
		}
		if ( UPLOAD_ERR_OK !== (int) $file['error'] ) {
			self::back( in_array( (int) $file['error'], array( UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE ), true ) ? 'too_big' : 'upload_error' );
		}
		if ( ! is_uploaded_file( $file['tmp_name'] ) ) {
			self::back( 'upload_error' );
		}

		$size = filesize( $file['tmp_name'] );
		if ( ! $size || $size > SMP_Plugin::max_bytes() ) {
			self::back( $size ? 'too_big' : 'empty' );
		}

		$name = sanitize_file_name( wp_unslash( $file['name'] ) );
		$ext  = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
		if ( ! in_array( $ext, array( 'html', 'htm' ), true ) ) {
			self::back( 'bad_type' );
		}

		// Check real content type, not the browser-supplied one.
		if ( function_exists( 'finfo_open' ) ) {
			$finfo = finfo_open( FILEINFO_MIME_TYPE );
			$mime  = $finfo ? finfo_file( $finfo, $file['tmp_name'] ) : '';
			if ( $finfo ) {
				finfo_close( $finfo );
			}
			if ( ! in_array( $mime, array( 'text/html', 'text/plain', 'text/xml', 'application/xhtml+xml' ), true ) ) {
				self::back( 'bad_type' );
			}
		}

		$raw = file_get_contents( $file['tmp_name'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( ! is_string( $raw ) || '' === trim( $raw ) ) {
			self::back( 'empty' );
		}

		// Strip UTF-8 BOM, reject binary / invalid encodings / server-side code.
		$raw = preg_replace( '/^\xEF\xBB\xBF/', '', $raw );
		if ( false !== strpos( $raw, "\0" ) || ! wp_check_invalid_utf8( $raw ) || preg_match( '/<\?(php|=)|<%/i', $raw ) ) {
			self::back( 'bad_content' );
		}

		$clean = SMP_Sanitizer::sanitize( $raw );
		if ( is_wp_error( $clean ) ) {
			self::back( 'bad_content' );
		}

		// Stored in the DB (not autoloaded), never as a file in a web-accessible folder.
		update_option( SMP_Plugin::OPTION_HTML, $clean, false );
		update_option(
			SMP_Plugin::OPTION_META,
			array(
				'name'     => $name,
				'size'     => strlen( $clean ),
				'time'     => time(),
				'user'     => get_current_user_id(),
				'modified' => SMP_Sanitizer::$removed > 0,
			),
			false
		);

		// Switch to the uploaded page automatically.
		$s             = SMP_Plugin::settings();
		$s['template'] = 'custom';
		update_option( SMP_Plugin::OPTION_SETTINGS, $s );

		self::back( 'uploaded' );
	}

	public static function handle_delete() {
		self::guard( 'smp_delete' );
		delete_option( SMP_Plugin::OPTION_HTML );
		delete_option( SMP_Plugin::OPTION_META );

		$s = SMP_Plugin::settings();
		if ( 'custom' === $s['template'] ) {
			$s['template'] = SMP_Plugin::default_template();
			update_option( SMP_Plugin::OPTION_SETTINGS, $s );
		}
		self::back( 'deleted' );
	}

	public static function handle_preview() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'secure-maintenance-page' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'smp_preview' );
		$template = isset( $_GET['template'] ) ? sanitize_key( wp_unslash( $_GET['template'] ) ) : SMP_Plugin::default_template();
		SMP_Plugin::render( $template, false );
	}

	private static function messages() {
		return array(
			'uploaded'     => array( 'success', __( 'The file was uploaded, sanitized and saved.', 'secure-maintenance-page' ) ),
			'deleted'      => array( 'success', __( 'The uploaded file was deleted.', 'secure-maintenance-page' ) ),
			'no_file'      => array( 'error', __( 'No file was selected.', 'secure-maintenance-page' ) ),
			'too_big'      => array( 'error', __( 'The file is larger than the allowed size.', 'secure-maintenance-page' ) ),
			'empty'        => array( 'error', __( 'The file is empty.', 'secure-maintenance-page' ) ),
			'bad_type'     => array( 'error', __( 'Only .html and .htm files are accepted.', 'secure-maintenance-page' ) ),
			'bad_content'  => array( 'error', __( 'The file content is invalid (not UTF-8, binary data, or server-side code).', 'secure-maintenance-page' ) ),
			'upload_error' => array( 'error', __( 'The file could not be uploaded.', 'secure-maintenance-page' ) ),
		);
	}

	public static function status_notice() {
		if ( ! current_user_can( self::CAP ) || ! SMP_Plugin::is_enabled() ) {
			return;
		}
		$url = admin_url( 'options-general.php?page=' . self::SLUG );
		printf(
			'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
			esc_html__( 'Maintenance mode is active.', 'secure-maintenance-page' ),
			esc_html__( 'Visitors are seeing the maintenance page.', 'secure-maintenance-page' ),
			esc_url( $url ),
			esc_html__( 'Settings', 'secure-maintenance-page' )
		);
	}

	public static function admin_bar( $bar ) {
		if ( ! current_user_can( self::CAP ) || ! SMP_Plugin::is_enabled() ) {
			return;
		}
		$bar->add_node(
			array(
				'id'    => 'smp-status',
				'title' => '<span style="background:#d63638;color:#fff;padding:2px 8px;border-radius:3px;">' . esc_html__( 'Maintenance mode on', 'secure-maintenance-page' ) . '</span>',
				'href'  => admin_url( 'options-general.php?page=' . self::SLUG ),
			)
		);
	}

	private static function preview_url( $template ) {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action'   => 'smp_preview',
					'template' => $template,
				),
				admin_url( 'admin-post.php' )
			),
			'smp_preview'
		);
	}

	public static function render_page() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'secure-maintenance-page' ), '', array( 'response' => 403 ) );
		}

		$s        = SMP_Plugin::settings();
		$meta     = get_option( SMP_Plugin::OPTION_META, array() );
		$has      = SMP_Plugin::has_custom_html();
		$messages = self::messages();
		$notice   = isset( $_GET['smp_notice'] ) ? sanitize_key( wp_unslash( $_GET['smp_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only, mapped to fixed strings.
		$opt      = SMP_Plugin::OPTION_SETTINGS;
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Maintenance Mode', 'secure-maintenance-page' ); ?></h1>

			<?php if ( isset( $messages[ $notice ] ) ) : ?>
				<div class="notice notice-<?php echo esc_attr( $messages[ $notice ][0] ); ?> is-dismissible"><p><?php echo esc_html( $messages[ $notice ][1] ); ?></p></div>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Settings', 'secure-maintenance-page' ); ?></h2>
			<form method="post" action="options.php">
				<?php settings_fields( 'smp_settings_group' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Status', 'secure-maintenance-page' ); ?></th>
						<td><label><input type="checkbox" name="<?php echo esc_attr( $opt ); ?>[enabled]" value="1" <?php checked( $s['enabled'], 1 ); ?>> <?php esc_html_e( 'Enable maintenance mode', 'secure-maintenance-page' ); ?></label>
						<p class="description"><?php esc_html_e( 'Logged-in administrators see the normal site; everyone else sees the maintenance page with a 503 status.', 'secure-maintenance-page' ); ?></p></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Page to show', 'secure-maintenance-page' ); ?></th>
						<td>
							<?php foreach ( SMP_Plugin::templates() as $key => $label ) : ?>
								<?php $disabled = ( 'custom' === $key && ! $has ); ?>
								<p>
									<label>
										<input type="radio" name="<?php echo esc_attr( $opt ); ?>[template]" value="<?php echo esc_attr( $key ); ?>" <?php checked( $s['template'], $key ); ?> <?php disabled( $disabled ); ?>>
										<?php echo esc_html( $label ); ?>
									</label>
									<?php if ( ! $disabled ) : ?>
										&nbsp;<a href="<?php echo esc_url( self::preview_url( $key ) ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Preview', 'secure-maintenance-page' ); ?></a>
									<?php endif; ?>
								</p>
							<?php endforeach; ?>
							<p class="description"><?php esc_html_e( 'If no file has been uploaded, Template 1 in the site language is shown.', 'secure-maintenance-page' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="smp-retry"><?php esc_html_e( 'Estimated downtime (hours)', 'secure-maintenance-page' ); ?></label></th>
						<td><input id="smp-retry" type="number" min="1" max="168" name="<?php echo esc_attr( $opt ); ?>[retry_hours]" value="<?php echo esc_attr( $s['retry_hours'] ); ?>" class="small-text">
						<p class="description"><?php esc_html_e( 'Sent to search engines in the Retry-After header so SEO is not harmed.', 'secure-maintenance-page' ); ?></p></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'REST API and XML-RPC', 'secure-maintenance-page' ); ?></th>
						<td><label><input type="checkbox" name="<?php echo esc_attr( $opt ); ?>[block_rest]" value="1" <?php checked( $s['block_rest'], 1 ); ?>> <?php esc_html_e( 'Block for non-admins while in maintenance mode (recommended)', 'secure-maintenance-page' ); ?></label></td>
					</tr>
				</table>
				<?php submit_button( __( 'Save settings', 'secure-maintenance-page' ) ); ?>
			</form>

			<hr>
			<h2><?php esc_html_e( 'Upload a custom HTML file', 'secure-maintenance-page' ); ?></h2>
			<?php if ( $has && is_array( $meta ) ) : ?>
				<p>
					<?php esc_html_e( 'Current file:', 'secure-maintenance-page' ); ?>
					<code><?php echo esc_html( isset( $meta['name'] ) ? $meta['name'] : '' ); ?></code>
					(<?php echo esc_html( size_format( isset( $meta['size'] ) ? (int) $meta['size'] : 0 ) ); ?>,
					<?php echo esc_html( isset( $meta['time'] ) ? wp_date( get_option( 'date_format' ) . ' H:i', (int) $meta['time'] ) : '' ); ?>)
				</p>
				<?php if ( ! empty( $meta['modified'] ) ) : ?>
					<p class="description"><?php esc_html_e( 'Note: unsafe parts of the file (such as scripts and forms) were removed during sanitization. Use the preview to check the result.', 'secure-maintenance-page' ); ?></p>
				<?php endif; ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Delete the file?', 'secure-maintenance-page' ) ); ?>');">
					<input type="hidden" name="action" value="smp_delete">
					<?php wp_nonce_field( 'smp_delete' ); ?>
					<?php submit_button( __( 'Delete uploaded file', 'secure-maintenance-page' ), 'delete', 'submit', false ); ?>
				</form>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data" style="margin-top:1em">
				<input type="hidden" name="action" value="smp_upload">
				<input type="hidden" name="MAX_FILE_SIZE" value="<?php echo esc_attr( SMP_Plugin::max_bytes() ); ?>">
				<?php wp_nonce_field( 'smp_upload' ); ?>
				<input type="file" name="smp_html_file" accept=".html,.htm,text/html" required>
				<?php submit_button( $has ? __( 'Replace file', 'secure-maintenance-page' ) : __( 'Upload file', 'secure-maintenance-page' ), 'primary', 'submit', false ); ?>
				<p class="description">
					<?php
					printf(
						/* translators: %s: max size */
						esc_html__( 'Only .html or .htm, up to %s. Scripts (JavaScript), forms, iframes and on* event handlers are removed for security. CSS (inline or linked over https) and images are allowed. You can use {{site_name}} and {{year}} in the text.', 'secure-maintenance-page' ),
						esc_html( size_format( SMP_Plugin::max_bytes() ) )
					);
					?>
				</p>
			</form>
		</div>
		<?php
	}
}
