# Restyle All Examples to Locke Brand

## What's Already Done

### Angular example (`examples/angular/`) — COMPLETE
- Single email field (replaces userId + username)
- Locke brand: gradient bg, frosted glass card, Merriweather/Inter fonts, animated teal/dark CTAs
- Files changed: `src/index.html` (Google Fonts), `src/styles.css` (global brand + @property), `src/app/app.component.ts` (template + styles + logic)

### SDK fix (`packages/sdk-js/`) — COMPLETE
- Discoverable credential flow: SDK sends `challenge` as lookup key (not `credential.id`) when no userId provided
- IIFE bundle rebuilt and copied to `examples/shared/passkey.js`

### Gateway session scoping (`../gateway/`) — COMPLETE
- `redis/sessions.go`: Added `ScopedSessionStore`, `RPID` field on `Session` struct, scoped user-set keys
- `main.go`: `multiTenantWithSessions` creates per-request scoped session store, `sessionIssuer` uses it, `handleLogoutAll` uses rpID from session

### Server-go duplicate rejection (`packages/server-go/`) — COMPLETE
- `BeginRegistration` checks `CredentialStore.GetByUser(userId)` — returns 409 Conflict if credentials already exist

---

## What Needs to Be Done

### Step 1: Update `examples/shared/style.css` — THE BIG WIN

Replace the current minimal CSS with full Locke brand styles. This one file change updates **15 server-only examples** at once.

The CSS should contain (copy from Angular example `app.component.ts` styles, plus the global styles from `styles.css`):

```css
/* === Global === */
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'Inter', system-ui, sans-serif;
  color: #1f2937;
  min-height: 100vh;
  background-image: linear-gradient(90deg, #E0EFFF 0%, #FEF8E0 100%);
  -webkit-font-smoothing: antialiased;
}

@property --border-angle {
  syntax: '<angle>';
  initial-value: 0deg;
  inherits: false;
}

@keyframes border-rotate {
  0% { --border-angle: 0deg; }
  100% { --border-angle: 360deg; }
}

/* === Layout === */
.page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
}

.card {
  width: 100%;
  max-width: 440px;
  background: rgba(255, 255, 255, 0.45);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.6);
  border-radius: 16px;
  padding: 40px 36px;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
  animation: fadeUp 0.5s cubic-bezier(0.22, 1, 0.36, 1);
}

@keyframes fadeUp {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
}

@media (prefers-reduced-motion: reduce) {
  .card { animation: none; }
}

/* === Typography === */
h1 {
  font-family: 'Merriweather', Georgia, serif;
  font-size: 1.75rem;
  font-weight: 700;
  color: #111827;
  margin-bottom: 4px;
}

.subtitle {
  font-size: 0.875rem;
  color: #6b7280;
  margin-bottom: 32px;
}

/* === Form === */
.field {
  margin-bottom: 24px;
}

.field label {
  display: block;
  font-size: 0.8rem;
  font-weight: 600;
  color: #374151;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 6px;
}

.field input {
  width: 100%;
  padding: 12px 16px;
  border: 1.5px solid rgba(0, 0, 0, 0.1);
  border-radius: 10px;
  font-size: 0.95rem;
  font-family: 'Inter', system-ui, sans-serif;
  color: #1f2937;
  background: rgba(255, 255, 255, 0.7);
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
  box-sizing: border-box;
}

.field input:focus {
  outline: none;
  border-color: #0891b2;
  box-shadow: 0 0 0 3px rgba(8, 145, 178, 0.1);
}

.field input::placeholder { color: #9ca3af; }

/* === Buttons === */
.actions {
  display: flex;
  flex-direction: column;
}

.btn-primary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  padding: 14px 28px;
  font-weight: 500;
  font-size: 15px;
  font-family: 'Inter', system-ui, sans-serif;
  color: white;
  background: #0891b2;
  border-radius: 10px;
  border: none;
  cursor: pointer;
  position: relative;
  z-index: 1;
  transition: color 0.3s ease, background 0.3s ease;
}

.btn-primary::before {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 10px;
  padding: 2px;
  background: conic-gradient(from var(--border-angle), #0e7490 0deg, #0e7490 140deg, #a5f3fc 180deg, #0e7490 220deg, #0e7490 360deg);
  -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  opacity: 0;
  transition: opacity 0.3s ease;
  animation: border-rotate 4s linear infinite;
}

.btn-primary:hover:not(:disabled) { background: transparent; color: #0e7490; }
.btn-primary:hover:not(:disabled)::before { opacity: 1; }
.btn-primary:active:not(:disabled) { transform: scale(0.98); }

.btn-secondary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  padding: 14px 28px;
  font-weight: 500;
  font-size: 15px;
  font-family: 'Inter', system-ui, sans-serif;
  color: white;
  background: #1f2937;
  border-radius: 10px;
  border: none;
  cursor: pointer;
  position: relative;
  z-index: 1;
  transition: color 0.3s ease, background 0.3s ease;
}

.btn-secondary::before {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 10px;
  padding: 2px;
  background: conic-gradient(from var(--border-angle), #374151 0deg, #374151 140deg, #d1d5db 180deg, #374151 220deg, #374151 360deg);
  -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  opacity: 0;
  transition: opacity 0.3s ease;
  animation: border-rotate 6s linear infinite;
}

.btn-secondary:hover:not(:disabled) { background: transparent; color: #1f2937; }
.btn-secondary:hover:not(:disabled)::before { opacity: 1; }
.btn-secondary:active:not(:disabled) { transform: scale(0.98); }

.btn-primary:disabled,
.btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

/* === Divider === */
.divider {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 16px 0;
}

.divider::before,
.divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: linear-gradient(to right, transparent, rgba(0, 0, 0, 0.1), transparent);
}

.divider span {
  font-size: 0.8rem;
  color: #9ca3af;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

/* === Status messages === */
.status {
  margin-top: 20px;
  padding: 12px 16px;
  border-radius: 10px;
  font-size: 0.875rem;
  line-height: 1.4;
  display: none;
}

.status.visible { display: block; }

.success {
  background: rgba(16, 185, 129, 0.1);
  color: #065f46;
  border: 1px solid rgba(16, 185, 129, 0.2);
}

.error {
  background: rgba(239, 68, 68, 0.1);
  color: #991b1b;
  border: 1px solid rgba(239, 68, 68, 0.2);
}

/* === Signed-in state === */
.signed-in { text-align: center; }

.signed-in-badge {
  display: inline-block;
  padding: 6px 16px;
  background: rgba(8, 145, 178, 0.1);
  color: #0891b2;
  font-size: 0.8rem;
  font-weight: 600;
  border-radius: 9999px;
  margin-bottom: 16px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.signed-in-email {
  font-size: 1.1rem;
  font-weight: 600;
  color: #111827;
  margin-bottom: 24px;
  word-break: break-all;
}

.loading {
  text-align: center;
  color: #6b7280;
  padding: 20px 0;
}
```

### Step 2: Write canonical `index.html` for server-only examples

Create one canonical template. The vanilla JS needs updating too — single email field, discoverable login support.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>open-passkey — FRAMEWORK_NAME Example</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Merriweather:ital,wght@0,400;0,700;1,400&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="page">
    <div class="card">
      <h1>open-passkey</h1>
      <p class="subtitle">FRAMEWORK_NAME Example</p>

      <div id="auth-form">
        <div class="field">
          <label for="email">Email</label>
          <input id="email" type="email" placeholder="you@example.com">
        </div>
        <div class="actions">
          <button class="btn-primary" onclick="doRegister()">Create Passkey</button>
          <div class="divider"><span>or</span></div>
          <button class="btn-secondary" onclick="doLogin()">Sign in with Passkey</button>
        </div>
        <div id="status" class="status"></div>
      </div>

      <div id="signed-in" style="display: none">
        <div class="signed-in">
          <div class="signed-in-badge">Authenticated</div>
          <div class="signed-in-email" id="signed-in-email"></div>
          <button class="btn-secondary" onclick="doLogout()">Sign Out</button>
        </div>
      </div>
    </div>
  </div>

  <script src="/passkey.js"></script>
  <script>
    const passkey = new OpenPasskey.PasskeyClient({ baseUrl: '/passkey' });

    // Check for existing session on load
    passkey.getSession()
      .then(session => { if (session) showSignedIn(session.userId); })
      .catch(() => {});

    function showStatus(msg, type) {
      const el = document.getElementById('status');
      el.textContent = msg;
      el.className = 'status visible ' + type;
    }

    function showSignedIn(userId) {
      document.getElementById('auth-form').style.display = 'none';
      document.getElementById('signed-in').style.display = 'block';
      document.getElementById('signed-in-email').textContent = userId;
    }

    function doRegister() {
      const email = document.getElementById('email').value;
      if (!email) { showStatus('Please enter an email', 'error'); return; }
      passkey.register(email, email)
        .then(() => showStatus('Registered! You can now sign in.', 'success'))
        .catch(err => showStatus(err.message, 'error'));
    }

    function doLogin() {
      const email = document.getElementById('email').value;
      passkey.authenticate(email || undefined)
        .then(() => passkey.getSession())
        .then(session => { if (session) showSignedIn(session.userId); })
        .catch(err => showStatus(err.message, 'error'));
    }

    function doLogout() {
      passkey.logout().then(() => {
        document.getElementById('auth-form').style.display = 'block';
        document.getElementById('signed-in').style.display = 'none';
        document.getElementById('status').className = 'status';
      });
    }
  </script>
</body>
</html>
```

### Step 3: Copy canonical HTML to all 15 server-only examples

Replace FRAMEWORK_NAME in title and subtitle for each:

| File path | FRAMEWORK_NAME |
|-----------|---------------|
| `express/public/index.html` | Express |
| `fastify/public/index.html` | Fastify |
| `hono/public/index.html` | Hono |
| `nestjs/public/index.html` | NestJS |
| `nethttp/public/index.html` | Go net/http |
| `echo/public/index.html` | Echo |
| `chi/public/index.html` | Chi |
| `gin/public/index.html` | Gin |
| `fiber/public/index.html` | Fiber |
| `flask/static/index.html` | Flask |
| `fastapi/static/index.html` | FastAPI |
| `django/static/index.html` | Django |
| `axum/static/index.html` | Axum |
| `spring/src/main/resources/static/index.html` | Spring |
| `aspnet/wwwroot/index.html` | ASP.NET |

### Step 4: Update Astro example

`astro/src/pages/index.astro` — Same HTML/JS as canonical template but wrapped in Astro page syntax. Uses `<script is:inline>` for the vanilla JS.

### Step 5: Update frontend framework examples (4)

Each needs the same changes as Angular but in their framework's idiom:

**React** (`examples/react/`):
- `src/App.tsx`: Single `email` state, pass to hooks. Replace inline styles with brand CSS (can use `<style>` in index.html or CSS module).
- `index.html`: Add Google Fonts links.
- Template: same card/field/buttons/divider/status structure as Angular.

**Vue** (`examples/vue/`):
- `src/App.vue`: Single `email` ref, pass to composables. Brand CSS in `<style>` block.
- `index.html`: Add Google Fonts links.

**Solid** (`examples/solid/`):
- `src/App.tsx`: Single `email` signal, pass to primitives. Brand CSS via `<style>` in index.html or inline.
- `index.html`: Add Google Fonts links.

**SvelteKit** (`examples/sveltekit/`):
- `src/routes/+page.svelte`: Single `email` variable, pass to store. Brand CSS in `<style>` block.
- `src/app.html`: Add Google Fonts links.

### Step 6: Update meta-framework examples (3)

**Next.js** (`examples/nextjs/`):
- `app/page.tsx`: Same as React. Brand CSS via global stylesheet or inline.
- `app/layout.tsx`: Add Google Fonts (can use `next/font/google` or `<link>` tags).

**Nuxt** (`examples/nuxt/`):
- `pages/index.vue`: Same as Vue.
- `nuxt.config.ts` or `app.vue`: Add Google Fonts links.

**Remix** (`examples/remix/`):
- `app/routes/_index.tsx`: Same as React.
- `app/root.tsx`: Add Google Fonts links.

## File Reference

### Brand CSS source of truth
- Website: `/Users/connor/Locke/MONOREPO/website/css/styles.css` (lines 160-317 for button animations)
- Angular example: `examples/angular/src/app/app.component.ts` (complete component CSS)
- Angular global: `examples/angular/src/styles.css` (@property + @keyframes)

### Files that need Google Fonts added
- All 15 server-only HTML files (in `<head>`)
- `examples/react/index.html`
- `examples/vue/index.html`
- `examples/solid/index.html`
- `examples/sveltekit/src/app.html`
- `examples/nextjs/app/layout.tsx`
- `examples/nuxt/nuxt.config.ts` or `app.vue`
- `examples/remix/app/root.tsx`
- `examples/astro/src/pages/index.astro`
