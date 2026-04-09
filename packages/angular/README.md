# @open-passkey/angular

Angular components and service for passkey (WebAuthn/FIDO2) authentication with post-quantum cryptography support.

Provides headless (renderless) components using content projection and a signal-based service wrapping `@open-passkey/sdk`.

## Install

```bash
npm install @open-passkey/angular @open-passkey/sdk
```

## Quick Start

Add passkeys to your Angular app **without running your own backend**. [Locke Gateway](https://gateway.locke.id) is a free hosted passkey server:

```typescript
import { providePasskey } from "@open-passkey/angular";

bootstrapApplication(AppComponent, {
  providers: [
    providePasskey({ provider: "locke-gateway", rpId: "example.com" }),
  ],
});
```

### Self-hosted

If you're running your own passkey server:

```typescript
providePasskey({ baseUrl: "/passkey" })
```

### Register (headless component)

```html
<open-passkey-register
  [userId]="'user-123'"
  [username]="'alice@example.com'"
  (registered)="onRegistered($event)"
  (error)="onError($event)"
>
  <button (click)="register()">Create Passkey</button>
</open-passkey-register>
```

### Login (headless component)

```html
<open-passkey-login
  (authenticated)="onAuthenticated($event)"
  (error)="onError($event)"
>
  <button (click)="login()">Sign in with Passkey</button>
</open-passkey-login>
```

### Service (programmatic)

```typescript
import { PasskeyService } from "@open-passkey/angular";

@Component({ ... })
export class MyComponent {
  private passkey = inject(PasskeyService);

  async register() {
    const result = await this.passkey.register("user-123", "alice@example.com");
  }

  async login() {
    const result = await this.passkey.authenticate();
  }

  async checkSession() {
    const session = await this.passkey.getSession();
  }

  async logout() {
    await this.passkey.logout();
  }
}
```

## Exports

| Export | Type | Description |
|--------|------|-------------|
| `providePasskey(config)` | Provider | App-level configuration |
| `PasskeyService` | Injectable | Programmatic passkey operations + session |
| `PasskeyRegisterComponent` | Component | Headless registration UI |
| `PasskeyLoginComponent` | Component | Headless login UI |

## Related Packages

| Package | Description |
|---------|-------------|
| [@open-passkey/sdk](https://www.npmjs.com/package/@open-passkey/sdk) | Browser SDK (peer dependency) |
| [@open-passkey/express](https://www.npmjs.com/package/@open-passkey/express) | Express server middleware |
| [@open-passkey/nestjs](https://www.npmjs.com/package/@open-passkey/nestjs) | NestJS server module |

## License

MIT
