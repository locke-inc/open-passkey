<?php

declare(strict_types=1);

namespace OpenPasskey\WordPress;

class CredentialTable
{
    public static function create(): void
    {
        global $wpdb;
        $table = $wpdb->prefix . 'passkey_credentials';
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            credential_id varchar(1400) NOT NULL,
            public_key_cose mediumtext NOT NULL,
            sign_count int unsigned NOT NULL DEFAULT 0,
            user_id varchar(255) NOT NULL,
            prf_salt varchar(64) DEFAULT NULL,
            prf_supported tinyint(1) NOT NULL DEFAULT 0,
            friendly_name varchar(255) DEFAULT NULL,
            last_used_at datetime DEFAULT NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY credential_id (credential_id(255)),
            KEY user_id (user_id)
        ) {$charset};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }
}
