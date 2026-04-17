<?php

declare(strict_types=1);

namespace OpenPasskey\WordPress;

class AdminSettings
{
    public function __construct()
    {
        add_action('admin_init', [$this, 'registerSettings']);
        add_options_page(
            __('Passkey Settings', 'open-passkey'),
            __('Passkey', 'open-passkey'),
            'manage_options',
            'open-passkey',
            [$this, 'renderPage'],
        );
    }

    public function registerSettings(): void
    {
        register_setting('open_passkey', 'open_passkey_settings');

        add_settings_section(
            'open_passkey_main',
            __('WebAuthn Configuration', 'open-passkey'),
            null,
            'open-passkey',
        );

        $fields = [
            'rp_id' => ['label' => __('RP ID', 'open-passkey'), 'default' => wp_parse_url(home_url(), PHP_URL_HOST)],
            'rp_display_name' => ['label' => __('RP Display Name', 'open-passkey'), 'default' => get_bloginfo('name')],
            'origin' => ['label' => __('Origin', 'open-passkey'), 'default' => home_url()],
        ];

        foreach ($fields as $key => $field) {
            add_settings_field(
                "open_passkey_{$key}",
                $field['label'],
                function () use ($key, $field) {
                    $settings = get_option('open_passkey_settings', []);
                    $value = esc_attr($settings[$key] ?? $field['default']);
                    echo "<input type='text' name='open_passkey_settings[{$key}]' value='{$value}' class='regular-text'>";
                },
                'open-passkey',
                'open_passkey_main',
            );
        }
    }

    public function renderPage(): void
    {
        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('Passkey Settings', 'open-passkey') . '</h1>';
        echo '<form method="post" action="options.php">';
        settings_fields('open_passkey');
        do_settings_sections('open-passkey');
        submit_button();
        echo '</form>';
        echo '</div>';
    }
}
