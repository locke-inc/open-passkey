<?php

declare(strict_types=1);

namespace OpenPasskey\WordPress;

use OpenPasskey\Base64Url;
use OpenPasskey\Server\PasskeyConfig;
use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\PasskeyHandler;
use OpenPasskey\Server\Session;
use OpenPasskey\Server\SessionConfig;
use WP_REST_Request;
use WP_REST_Response;

class RestApi
{
    private PasskeyHandler $handler;
    private PasskeyConfig $config;

    public function __construct()
    {
        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    public function registerRoutes(): void
    {
        $this->config = $this->buildConfig();
        $this->handler = new PasskeyHandler($this->config);
        $ns = 'open-passkey/v1';

        register_rest_route($ns, '/register/begin', [
            'methods' => 'POST',
            'callback' => [$this, 'beginRegistration'],
            'permission_callback' => 'is_user_logged_in',
        ]);
        register_rest_route($ns, '/register/finish', [
            'methods' => 'POST',
            'callback' => [$this, 'finishRegistration'],
            'permission_callback' => 'is_user_logged_in',
        ]);
        register_rest_route($ns, '/login/begin', [
            'methods' => 'POST',
            'callback' => [$this, 'beginAuthentication'],
            'permission_callback' => '__return_true',
        ]);
        register_rest_route($ns, '/login/finish', [
            'methods' => 'POST',
            'callback' => [$this, 'finishAuthentication'],
            'permission_callback' => '__return_true',
        ]);
        register_rest_route($ns, '/session', [
            'methods' => 'GET',
            'callback' => [$this, 'getSession'],
            'permission_callback' => '__return_true',
        ]);
        register_rest_route($ns, '/logout', [
            'methods' => 'POST',
            'callback' => [$this, 'logout'],
            'permission_callback' => '__return_true',
        ]);
        register_rest_route($ns, '/credentials/(?P<credential_id>[^/]+)/name', [
            'methods' => 'PUT',
            'callback' => [$this, 'renameCredential'],
            'permission_callback' => 'is_user_logged_in',
        ]);
        register_rest_route($ns, '/credentials/(?P<credential_id>[^/]+)', [
            'methods' => 'DELETE',
            'callback' => [$this, 'deleteCredential'],
            'permission_callback' => 'is_user_logged_in',
        ]);
    }

    public function beginRegistration(WP_REST_Request $request): WP_REST_Response
    {
        $body = $request->get_json_params();
        $userId = (string) get_current_user_id();
        $existing = $this->config->credentialStore->getByUser($userId);
        if (count($existing) >= 5) {
            return new WP_REST_Response(['error' => 'Maximum of 5 passkeys per user'], 409);
        }

        try {
            return new WP_REST_Response($this->handler->beginRegistration(
                $body['userId'] ?? '',
                $body['username'] ?? '',
            ));
        } catch (PasskeyError $e) {
            return new WP_REST_Response(['error' => $e->getMessage()], $e->statusCode);
        }
    }

    public function finishRegistration(WP_REST_Request $request): WP_REST_Response
    {
        $body = $request->get_json_params();
        try {
            $result = $this->handler->finishRegistration(
                $body['userId'] ?? '',
                $body['credential'] ?? [],
                $body['prfSupported'] ?? false,
            );
        } catch (PasskeyError $e) {
            return new WP_REST_Response(['error' => $e->getMessage()], $e->statusCode);
        }

        return $this->withSessionCookie($result);
    }

    public function beginAuthentication(WP_REST_Request $request): WP_REST_Response
    {
        $body = $request->get_json_params();
        try {
            return new WP_REST_Response($this->handler->beginAuthentication($body['userId'] ?? ''));
        } catch (PasskeyError $e) {
            return new WP_REST_Response(['error' => $e->getMessage()], $e->statusCode);
        }
    }

    public function finishAuthentication(WP_REST_Request $request): WP_REST_Response
    {
        $body = $request->get_json_params();
        try {
            $result = $this->handler->finishAuthentication(
                $body['userId'] ?? '',
                $body['credential'] ?? [],
            );
        } catch (PasskeyError $e) {
            return new WP_REST_Response(['error' => $e->getMessage()], $e->statusCode);
        }

        $wpUser = get_user_by('id', (int) $result['userId']);
        if ($wpUser) {
            wp_set_current_user($wpUser->ID);
            wp_set_auth_cookie($wpUser->ID, true);
            $result['redirect'] = admin_url();
        }

        return $this->withSessionCookie($result);
    }

    public function deleteCredential(WP_REST_Request $request): WP_REST_Response
    {
        $credentialIdB64 = $request->get_param('credential_id');
        $store = $this->config->credentialStore;

        try {
            $credentialId = Base64Url::decode($credentialIdB64);
            $cred = $store->get($credentialId);
        } catch (PasskeyError|\InvalidArgumentException $e) {
            return new WP_REST_Response(['error' => 'credential not found'], 404);
        }

        if ($cred->userId !== (string) get_current_user_id()) {
            return new WP_REST_Response(['error' => 'forbidden'], 403);
        }

        $store->delete($credentialId);
        return new WP_REST_Response(['success' => true]);
    }

    public function renameCredential(WP_REST_Request $request): WP_REST_Response
    {
        $credentialIdB64 = $request->get_param('credential_id');
        $body = $request->get_json_params();
        $name = trim($body['name'] ?? '');
        if ($name === '' || mb_strlen($name) > 255) {
            return new WP_REST_Response(['error' => 'name must be 1-255 characters'], 400);
        }

        $store = $this->config->credentialStore;
        if (!$store instanceof WpCredentialStore) {
            return new WP_REST_Response(['error' => 'unsupported store'], 500);
        }

        try {
            $credentialId = Base64Url::decode($credentialIdB64);
            $cred = $store->get($credentialId);
        } catch (PasskeyError|\InvalidArgumentException $e) {
            return new WP_REST_Response(['error' => 'credential not found'], 404);
        }

        if ($cred->userId !== (string) get_current_user_id()) {
            return new WP_REST_Response(['error' => 'forbidden'], 403);
        }

        $store->rename($credentialId, $name);
        return new WP_REST_Response(['success' => true]);
    }

    public function getSession(WP_REST_Request $request): WP_REST_Response
    {
        if ($this->config->session === null) {
            return new WP_REST_Response(['error' => 'session is not configured'], 500);
        }

        $token = Session::parseCookieToken($_SERVER['HTTP_COOKIE'] ?? null, $this->config->session);
        if ($token === null) {
            return new WP_REST_Response(['error' => 'no session cookie'], 401);
        }

        try {
            $data = $this->handler->getSessionTokenData($token);
        } catch (PasskeyError|\ValueError $e) {
            return new WP_REST_Response(['error' => 'invalid session'], 401);
        }

        return new WP_REST_Response(['userId' => $data->userId, 'authenticated' => true]);
    }

    public function logout(): WP_REST_Response
    {
        if ($this->config->session === null) {
            return new WP_REST_Response(['error' => 'session is not configured'], 500);
        }

        header('Set-Cookie: ' . Session::buildClearCookieHeader($this->config->session), false);
        return new WP_REST_Response(['success' => true]);
    }

    private function buildConfig(): PasskeyConfig
    {
        $settings = get_option('open_passkey_settings', []);

        $sessionConfig = null;
        if (!empty($settings['session_secret'])) {
            $sessionConfig = new SessionConfig(
                secret: $settings['session_secret'],
                secure: is_ssl(),
            );
        }

        return new PasskeyConfig(
            rpId: $settings['rp_id'] ?? wp_parse_url(home_url(), PHP_URL_HOST),
            rpDisplayName: $settings['rp_display_name'] ?? get_bloginfo('name'),
            origin: $settings['origin'] ?? home_url(),
            challengeStore: new WpTransientChallengeStore(),
            credentialStore: new WpCredentialStore(),
            allowMultipleCredentials: true,
            session: $sessionConfig,
        );
    }

    private function withSessionCookie(array $result): WP_REST_Response
    {
        if ($this->config->session !== null && isset($result['sessionToken'])) {
            $token = $result['sessionToken'];
            unset($result['sessionToken']);
            header('Set-Cookie: ' . Session::buildSetCookieHeader($token, $this->config->session), false);
        }

        return new WP_REST_Response($result);
    }
}
