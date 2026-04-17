<?php
/*
 * Plugin Name: Open Passkey
 * Plugin URI: https://github.com/locke-inc/open-passkey
 * Description: Add passwordless passkey authentication to WordPress
 * Version: 0.1.0
 * Requires at least: 6.4
 * Tested up to: 6.8
 * Requires PHP: 8.1
 * Author: Locke
 * Author URI: https://lockeidentity.com
 * License: MIT
 * Text Domain: open-passkey
 * Domain Path: /languages
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/vendor/autoload.php';

register_activation_hook(__FILE__, function () {
    OpenPasskey\WordPress\CredentialTable::create();

    $settings = get_option('open_passkey_settings', []);
    if (empty($settings['session_secret'])) {
        $settings['session_secret'] = bin2hex(random_bytes(32));
        update_option('open_passkey_settings', $settings);
    }

    $rpId = $settings['rp_id'] ?? wp_parse_url(home_url(), PHP_URL_HOST);
    if (in_array($rpId, ['localhost', '127.0.0.1', '::1'], true)) {
        set_transient('open_passkey_activation_notice', true, 300);
    }
});

add_action('admin_notices', function () {
    if (!get_transient('open_passkey_activation_notice')) {
        return;
    }
    if (!current_user_can('manage_options')) {
        return;
    }
    delete_transient('open_passkey_activation_notice');
    $settings_url = esc_url(admin_url('options-general.php?page=open-passkey'));
    printf(
        '<div class="notice notice-warning is-dismissible"><p>%s <a href="%s">%s</a></p></div>',
        esc_html__('Open Passkey: Your RP ID is currently set to localhost. Passkeys registered on localhost will not work in production.', 'open-passkey'),
        $settings_url,
        esc_html__('Configure settings', 'open-passkey'),
    );
});

add_action('init', function () {
    new OpenPasskey\WordPress\RestApi();
    new OpenPasskey\WordPress\LoginIntegration();
    new OpenPasskey\WordPress\ProfileIntegration();
});

add_action('admin_menu', function () {
    new OpenPasskey\WordPress\AdminSettings();
});
