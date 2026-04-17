<?php

declare(strict_types=1);

namespace OpenPasskey\WordPress;

class LoginIntegration
{
    public function __construct()
    {
        add_action('login_enqueue_scripts', [$this, 'enqueueScripts']);
        add_action('login_form', [$this, 'renderPasskeyButton']);
        add_action('login_footer', [$this, 'renderPasskeyScript']);
    }

    public function enqueueScripts(): void
    {
        wp_enqueue_script(
            'open-passkey-sdk',
            plugins_url('assets/passkey.js', dirname(__FILE__)),
            [],
            '0.1.0',
            false,
        );
    }

    public function renderPasskeyButton(): void
    {
        ?>
        <div id="open-passkey-login" style="text-align: center; margin: 16px 0; display: none;">
            <div style="display: flex; align-items: center; margin: 12px 0;">
                <hr style="flex: 1; border-top: 1px solid #ddd;">
                <span style="padding: 0 12px; color: #999; font-size: 13px;"><?php esc_html_e('or', 'open-passkey'); ?></span>
                <hr style="flex: 1; border-top: 1px solid #ddd;">
            </div>
            <button type="button" id="passkey-login-btn" class="button button-secondary" style="width: 100%;">
                <?php esc_html_e('Sign in with Passkey', 'open-passkey'); ?>
            </button>
            <div id="passkey-status" style="margin-top: 8px; color: #d63638; font-size: 13px;"></div>
        </div>
        <?php
    }

    public function renderPasskeyScript(): void
    {
        $api_url = esc_url(rest_url('open-passkey/v1'));
        $redirect = esc_url(admin_url());
        ?>
        <script>
        (function() {
            if (!window.PublicKeyCredential) return;

            var container = document.getElementById('open-passkey-login');
            if (container) container.style.display = '';

            var passkey = new OpenPasskey.PasskeyClient({ baseUrl: <?php echo wp_json_encode($api_url); ?> });
            var btn = document.getElementById('passkey-login-btn');
            var status = document.getElementById('passkey-status');
            if (!btn) return;

            btn.addEventListener('click', async function() {
                btn.disabled = true;
                status.textContent = '';
                try {
                    var result = await passkey.authenticate();
                    var redirect = new URLSearchParams(window.location.search).get('redirect_to') || result.redirect || <?php echo wp_json_encode($redirect); ?>;
                    window.location.href = redirect;
                } catch (err) {
                    status.textContent = err.message || <?php echo wp_json_encode(__('Passkey authentication failed', 'open-passkey')); ?>;
                    btn.disabled = false;
                }
            });
        })();
        </script>
        <?php
    }
}
