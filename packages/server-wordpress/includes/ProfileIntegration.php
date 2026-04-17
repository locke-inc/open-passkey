<?php

declare(strict_types=1);

namespace OpenPasskey\WordPress;

use OpenPasskey\Base64Url;

class ProfileIntegration
{
    public function __construct()
    {
        add_action('show_user_profile', [$this, 'renderPasskeySection']);
        add_action('admin_enqueue_scripts', [$this, 'enqueueScripts']);
    }

    public function enqueueScripts(string $hook): void
    {
        if ($hook !== 'profile.php' && $hook !== 'user-edit.php') {
            return;
        }

        wp_enqueue_script(
            'open-passkey-sdk',
            plugins_url('assets/passkey.js', dirname(__FILE__)),
            [],
            '0.1.0',
            true,
        );

        wp_enqueue_script(
            'open-passkey-profile',
            plugins_url('assets/profile.js', dirname(__FILE__)),
            ['open-passkey-sdk'],
            '0.1.0',
            true,
        );

        $user = wp_get_current_user();
        wp_localize_script('open-passkey-profile', 'openPasskeyProfile', [
            'apiUrl' => rest_url('open-passkey/v1'),
            'userId' => (string) $user->ID,
            'username' => $user->user_login,
            'nonce' => wp_create_nonce('wp_rest'),
            'maxPasskeys' => 5,
            'i18n' => [
                'confirmRemove' => __('Remove this passkey?', 'open-passkey'),
                'registerFailed' => __('Failed to register passkey', 'open-passkey'),
                'removeFailed' => __('Failed to remove passkey', 'open-passkey'),
                'renameFailed' => __('Failed to rename passkey', 'open-passkey'),
                'enterName' => __('Enter a name for this passkey:', 'open-passkey'),
            ],
        ]);
    }

    public function renderPasskeySection(\WP_User $user): void
    {
        $store = new WpCredentialStore();
        $credentials = $store->getByUser((string) $user->ID);
        $count = count($credentials);
        $max = 5;
        ?>
        <h2><?php esc_html_e('Passkey Authentication', 'open-passkey'); ?></h2>
        <table class="form-table">
            <tr>
                <th><?php esc_html_e('Registered Passkeys', 'open-passkey'); ?></th>
                <td>
                    <p class="description" style="margin-bottom: 8px;">
                        <?php
                        printf(
                            /* translators: %1$d: number of registered passkeys, %2$d: maximum allowed */
                            esc_html__('%1$d of %2$d passkeys registered', 'open-passkey'),
                            $count,
                            $max,
                        );
                        ?>
                    </p>
                    <?php if (empty($credentials)): ?>
                        <p class="description"><?php esc_html_e('No passkeys registered yet.', 'open-passkey'); ?></p>
                    <?php else: ?>
                        <style>.op-passkey-table th, .op-passkey-table td { padding-left: 12px; }</style>
                        <table class="widefat striped op-passkey-table" style="max-width: 700px; table-layout: fixed;">
                            <colgroup>
                                <col style="width: 35%;">
                                <col style="width: 22%;">
                                <col style="width: 25%;">
                                <col style="width: 18%;">
                            </colgroup>
                            <thead>
                                <tr>
                                    <th><?php esc_html_e('Name', 'open-passkey'); ?></th>
                                    <th><?php esc_html_e('Last Used', 'open-passkey'); ?></th>
                                    <th><?php esc_html_e('Created', 'open-passkey'); ?></th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($credentials as $cred):
                                    $credIdB64 = Base64Url::encode($cred->credentialId);
                                    $raw = $store->getRaw($credIdB64);
                                    $friendlyName = $raw['friendly_name'] ?? '';
                                    $lastUsed = $raw['last_used_at'] ?? null;
                                    $createdAt = $raw['created_at'] ?? '';
                                    $displayName = $friendlyName !== '' && $friendlyName !== null
                                        ? $friendlyName
                                        : substr($credIdB64, 0, 12) . '…';
                                ?>
                                    <tr>
                                        <td>
                                            <span class="passkey-name"><?php echo esc_html($displayName); ?></span>
                                            <button type="button"
                                                class="button-link passkey-rename-btn"
                                                data-credential-id="<?php echo esc_attr($credIdB64); ?>"
                                                title="<?php esc_attr_e('Rename', 'open-passkey'); ?>">
                                                <span class="dashicons dashicons-edit" style="font-size: 16px; width: 16px; height: 16px;"></span>
                                            </button>
                                        </td>
                                        <td>
                                            <?php if ($lastUsed): ?>
                                                <?php echo esc_html(human_time_diff(strtotime($lastUsed . ' UTC'), time())); ?>
                                                <?php esc_html_e('ago', 'open-passkey'); ?>
                                            <?php else: ?>
                                                <span style="color: #999;"><?php esc_html_e('Never', 'open-passkey'); ?></span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php echo esc_html(wp_date(get_option('date_format'), strtotime($createdAt . ' UTC'))); ?>
                                        </td>
                                        <td>
                                            <button type="button"
                                                class="button button-link-delete passkey-delete-btn"
                                                data-credential-id="<?php echo esc_attr($credIdB64); ?>">
                                                <?php esc_html_e('Remove', 'open-passkey'); ?>
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                    <?php if ($count < $max): ?>
                        <p style="margin-top: 12px;">
                            <button type="button" id="passkey-register-btn" class="button button-secondary">
                                <?php esc_html_e('Register New Passkey', 'open-passkey'); ?>
                            </button>
                        </p>
                    <?php else: ?>
                        <p class="description" style="margin-top: 8px;">
                            <?php esc_html_e('Maximum number of passkeys reached. Remove one to register another.', 'open-passkey'); ?>
                        </p>
                    <?php endif; ?>
                    <div id="passkey-profile-status" style="margin-top: 8px; color: #d63638; font-size: 13px;"></div>
                </td>
            </tr>
        </table>
        <?php
    }
}
