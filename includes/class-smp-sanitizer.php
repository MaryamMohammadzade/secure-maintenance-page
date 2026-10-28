<?php
/**
 * Allowlist-based HTML sanitizer for uploaded maintenance pages.
 *
 * wp_kses() is built for post content and strips <html>, <head>, <style>, <link>
 * and <meta>, which a full standalone page needs. This sanitizer keeps a full
 * document but removes everything that can execute code: scripts, event
 * handlers, javascript:/vbscript: URLs, embedded objects, frames, forms, SVG/MathML,
 * <base>, meta refresh and dangerous CSS constructs.
 */

defined( 'ABSPATH' ) || exit;

final class SMP_Sanitizer {

	/** Removed together with all of their content. */
	const DROP_TAGS = array(
		'script', 'noscript', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet',
		'form', 'input', 'button', 'select', 'option', 'textarea', 'base', 'svg', 'math',
		'template', 'portal', 'canvas', 'dialog', 'slot', 'param', 'xml', 'xss',
	);

	/** Void elements among DROP_TAGS: removed, but anything misparsed inside them is kept. */
	const VOID_DROP_TAGS = array( 'embed', 'input', 'param', 'base', 'frame' );

	/** Allowed tags. Unknown tags are unwrapped (their text is kept). */
	const ALLOWED_TAGS = array(
		'html', 'head', 'body', 'title', 'meta', 'link', 'style',
		'div', 'span', 'p', 'a', 'img', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
		'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'strong', 'em', 'b', 'i', 'u', 's', 'small', 'mark',
		'sub', 'sup', 'abbr', 'time', 'code', 'pre', 'blockquote', 'q', 'cite',
		'section', 'header', 'footer', 'main', 'article', 'aside', 'nav', 'figure', 'figcaption',
		'picture', 'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption', 'address', 'center',
	);

	const GLOBAL_ATTRS = array( 'class', 'id', 'style', 'title', 'lang', 'dir', 'role', 'hidden' );

	const TAG_ATTRS = array(
		'html' => array( 'lang', 'dir' ),
		'meta' => array( 'charset', 'name', 'content' ),
		'link' => array( 'rel', 'href', 'type', 'media', 'sizes', 'crossorigin' ),
		'a'    => array( 'href', 'target', 'rel' ),
		'img'  => array( 'src', 'alt', 'width', 'height', 'loading', 'decoding' ),
		'td'   => array( 'colspan', 'rowspan' ),
		'th'   => array( 'colspan', 'rowspan', 'scope' ),
		'ol'   => array( 'start', 'reversed', 'type' ),
		'time' => array( 'datetime' ),
		'abbr' => array( 'title' ),
	);

	/** Number of items removed during the last sanitize() call. */
	public static $removed = 0;

	const META_NAMES = array( 'viewport', 'description', 'robots', 'theme-color', 'color-scheme' );
	const LINK_RELS  = array( 'stylesheet', 'icon', 'shortcut icon', 'apple-touch-icon', 'preconnect' );

	/**
	 * @param string $html Raw HTML.
	 * @return string|WP_Error Sanitized full document.
	 */
	public static function sanitize( $html ) {
		if ( ! class_exists( 'DOMDocument' ) ) {
			return new WP_Error( 'smp_no_dom', __( 'The PHP DOM extension is not enabled on this server.', 'secure-maintenance-page' ) );
		}

		self::$removed = 0;
		$prev          = libxml_use_internal_errors( true );
		$doc  = new DOMDocument( '1.0', 'UTF-8' );
		// LIBXML_NONET: never fetch external resources while parsing.
		$ok = $doc->loadHTML( '<?xml encoding="UTF-8">' . $html, LIBXML_NONET | LIBXML_COMPACT );
		libxml_clear_errors();
		libxml_use_internal_errors( $prev );

		if ( ! $ok || ! $doc->documentElement ) {
			return new WP_Error( 'smp_parse', __( 'The HTML file could not be parsed.', 'secure-maintenance-page' ) );
		}
		$doc->encoding = 'UTF-8';

		$xpath = new DOMXPath( $doc );

		// Comments (IE conditional comments), processing instructions, CDATA, doctype.
		foreach ( iterator_to_array( $xpath->query( '//comment() | //processing-instruction()' ) ) as $node ) {
			$node->parentNode->removeChild( $node );
		}
		foreach ( iterator_to_array( $doc->childNodes ) as $node ) {
			if ( XML_DOCUMENT_TYPE_NODE === $node->nodeType || XML_PI_NODE === $node->nodeType ) {
				$doc->removeChild( $node );
			}
		}

		// Pass 1: drop dangerous elements with their content.
		foreach ( iterator_to_array( $doc->getElementsByTagName( '*' ) ) as $el ) {
			$name = strtolower( $el->nodeName );
			if ( in_array( $name, self::DROP_TAGS, true ) && $el->parentNode ) {
				if ( in_array( $name, self::VOID_DROP_TAGS, true ) ) {
					// libxml's HTML4 parser may nest following siblings inside these void tags; keep them.
					while ( $el->firstChild ) {
						$el->parentNode->insertBefore( $el->firstChild, $el );
					}
				}
				$el->parentNode->removeChild( $el );
				++self::$removed;
			}
		}

		// Pass 2: unwrap unknown tags, filter attributes, check special tags.
		foreach ( iterator_to_array( $doc->getElementsByTagName( '*' ) ) as $el ) {
			if ( ! $el->parentNode ) {
				continue;
			}
			$tag = strtolower( $el->nodeName );

			if ( ! in_array( $tag, self::ALLOWED_TAGS, true ) ) {
				self::unwrap( $el );
				continue;
			}

			self::filter_attributes( $el, $tag );

			if ( 'meta' === $tag && ! self::meta_ok( $el ) ) {
				$el->parentNode->removeChild( $el );
				++self::$removed;
				continue;
			}
			if ( 'link' === $tag && ! self::link_ok( $el ) ) {
				$el->parentNode->removeChild( $el );
				++self::$removed;
				continue;
			}
			if ( 'style' === $tag && self::css_is_dangerous( $el->textContent ) ) {
				$el->parentNode->removeChild( $el );
				++self::$removed;
				continue;
			}
		}

		$out = $doc->saveHTML( $doc->documentElement );
		if ( ! is_string( $out ) || '' === trim( $out ) ) {
			return new WP_Error( 'smp_empty', __( 'Nothing was left after sanitization.', 'secure-maintenance-page' ) );
		}

		return "<!DOCTYPE html>\n" . $out;
	}

	private static function unwrap( DOMElement $el ) {
		$parent = $el->parentNode;
		while ( $el->firstChild ) {
			$parent->insertBefore( $el->firstChild, $el );
		}
		$parent->removeChild( $el );
	}

	private static function filter_attributes( DOMElement $el, $tag ) {
		$allowed = array_merge( self::GLOBAL_ATTRS, isset( self::TAG_ATTRS[ $tag ] ) ? self::TAG_ATTRS[ $tag ] : array() );

		foreach ( iterator_to_array( $el->attributes ) as $attr ) {
			$name  = strtolower( $attr->nodeName );
			$value = $attr->nodeValue;

			$is_aria = ( 0 === strpos( $name, 'aria-' ) && preg_match( '/^aria-[a-z]+$/', $name ) );
			if ( ! $is_aria && ! in_array( $name, $allowed, true ) ) {
				$el->removeAttribute( $attr->nodeName );
				if ( 0 === strpos( $name, 'on' ) || 'http-equiv' === $name || 'formaction' === $name ) {
					++self::$removed;
				}
				continue;
			}

			if ( 'style' === $name && self::css_is_dangerous( $value ) ) {
				$el->removeAttribute( $attr->nodeName );
				++self::$removed;
				continue;
			}

			if ( 'href' === $name || 'src' === $name ) {
				$allow_data = ( 'img' === $tag && 'src' === $name );
				if ( ! self::url_ok( $value, $allow_data ) ) {
					$el->removeAttribute( $attr->nodeName );
					++self::$removed;
				}
			}
		}

		if ( 'a' === $tag && '_blank' === strtolower( (string) $el->getAttribute( 'target' ) ) ) {
			$el->setAttribute( 'rel', 'noopener noreferrer' );
		}
	}

	/**
	 * Allows relative URLs and http(s)/mailto/tel; optionally data:image/* (raster only).
	 */
	public static function url_ok( $url, $allow_data_image = false ) {
		// Browsers ignore control chars and whitespace inside the scheme ("java\tscript:").
		$clean = strtolower( preg_replace( '/[\x00-\x20\x7f]+/', '', html_entity_decode( (string) $url, ENT_QUOTES | ENT_HTML5, 'UTF-8' ) ) );

		if ( '' === $clean ) {
			return false;
		}
		if ( ! preg_match( '/^([a-z][a-z0-9+.\-]*):/', $clean, $m ) ) {
			return true; // Relative, protocol-relative, #anchor or ?query.
		}
		if ( in_array( $m[1], array( 'http', 'https', 'mailto', 'tel' ), true ) ) {
			return true;
		}
		if ( $allow_data_image && preg_match( '#^data:image/(png|jpe?g|gif|webp|avif);base64,[a-z0-9+/=]+$#', $clean ) ) {
			return true;
		}
		return false;
	}

	public static function css_is_dangerous( $css ) {
		$c = strtolower( html_entity_decode( (string) $css, ENT_QUOTES | ENT_HTML5, 'UTF-8' ) );
		$c = preg_replace( '#/\*.*?\*/#s', '', $c );   // Comments used to split keywords.
		$c = preg_replace( '/\\\\[0-9a-f]{1,6}\s?|\\\\/', '', $c ); // CSS escapes ("\6a avascript").
		$c = preg_replace( '/\s+/', '', $c );
		return (bool) preg_match( '/expression\(|javascript:|vbscript:|livescript:|behavior:|-moz-binding|data:text|data:application|data:image\/svg|<\/?style|<script/', $c );
	}

	private static function meta_ok( DOMElement $el ) {
		if ( $el->hasAttribute( 'charset' ) ) {
			$el->setAttribute( 'charset', 'utf-8' );
			$el->removeAttribute( 'name' );
			$el->removeAttribute( 'content' );
			return true;
		}
		// http-equiv (refresh, set-cookie, CSP override) is already removed by the attribute filter.
		return in_array( strtolower( trim( $el->getAttribute( 'name' ) ) ), self::META_NAMES, true );
	}

	private static function link_ok( DOMElement $el ) {
		$rel  = strtolower( trim( preg_replace( '/\s+/', ' ', $el->getAttribute( 'rel' ) ) ) );
		$href = trim( $el->getAttribute( 'href' ) );
		if ( ! in_array( $rel, self::LINK_RELS, true ) || '' === $href ) {
			return false;
		}
		// Only same-site relative or https resources.
		return 0 === stripos( $href, 'https://' ) || ( '/' === $href[0] && 0 !== strpos( $href, '//' ) ) || ! preg_match( '/^[a-z][a-z0-9+.\-]*:|^\/\//i', $href );
	}
}
