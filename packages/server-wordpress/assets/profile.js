(function () {
    var config = window.openPasskeyProfile;
    if (!config) return;

    if (!window.PublicKeyCredential) {
        var registerBtn = document.getElementById('passkey-register-btn');
        if (registerBtn) registerBtn.style.display = 'none';
        return;
    }

    var originalFetch = window.fetch;
    window.fetch = function (url, opts) {
        if (typeof url === 'string' && url.startsWith(config.apiUrl)) {
            opts = opts || {};
            opts.headers = new Headers(opts.headers || {});
            opts.headers.set('X-WP-Nonce', config.nonce);
        }
        return originalFetch.call(window, url, opts);
    };

    var passkey = new OpenPasskey.PasskeyClient({ baseUrl: config.apiUrl });
    var status = document.getElementById('passkey-profile-status');

    var registerBtn = document.getElementById('passkey-register-btn');
    if (registerBtn) {
        registerBtn.addEventListener('click', async function () {
            registerBtn.disabled = true;
            status.textContent = '';
            try {
                await passkey.register(config.userId, config.username);
                location.reload();
            } catch (err) {
                status.textContent = err.message || config.i18n.registerFailed;
                registerBtn.disabled = false;
            }
        });
    }

    document.querySelectorAll('.passkey-delete-btn').forEach(function (btn) {
        btn.addEventListener('click', async function () {
            var credentialId = btn.dataset.credentialId;
            if (!confirm(config.i18n.confirmRemove)) return;
            btn.disabled = true;
            try {
                var resp = await fetch(
                    config.apiUrl + '/credentials/' + encodeURIComponent(credentialId),
                    {
                        method: 'DELETE',
                        headers: { 'X-WP-Nonce': config.nonce },
                        credentials: 'include',
                    }
                );
                if (!resp.ok) {
                    var data = await resp.json();
                    throw new Error(data.error || config.i18n.removeFailed);
                }
                location.reload();
            } catch (err) {
                status.textContent = err.message || config.i18n.removeFailed;
                btn.disabled = false;
            }
        });
    });

    document.querySelectorAll('.passkey-rename-btn').forEach(function (btn) {
        btn.addEventListener('click', async function () {
            var credentialId = btn.dataset.credentialId;
            var nameSpan = btn.parentElement.querySelector('.passkey-name');
            var currentName = nameSpan.textContent;
            var newName = prompt(config.i18n.enterName, currentName);
            if (newName === null || newName.trim() === '') return;

            try {
                var resp = await fetch(
                    config.apiUrl + '/credentials/' + encodeURIComponent(credentialId) + '/name',
                    {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-WP-Nonce': config.nonce,
                        },
                        credentials: 'include',
                        body: JSON.stringify({ name: newName.trim() }),
                    }
                );
                if (!resp.ok) {
                    var data = await resp.json();
                    throw new Error(data.error || config.i18n.renameFailed);
                }
                nameSpan.textContent = newName.trim();
            } catch (err) {
                status.textContent = err.message || config.i18n.renameFailed;
            }
        });
    });
})();
