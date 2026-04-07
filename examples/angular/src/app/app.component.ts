import { Component, inject, OnInit, signal } from "@angular/core";
import {
  PasskeyRegisterComponent,
  PasskeyLoginComponent,
  PasskeyService,
  type PasskeyRegistrationResult,
  type PasskeyAuthenticationResult,
} from "@open-passkey/angular";

@Component({
  selector: "app-root",
  standalone: true,
  imports: [PasskeyRegisterComponent, PasskeyLoginComponent],
  template: `
    <div class="container">
      <h1>open-passkey</h1>
      <p class="subtitle">Angular Example</p>

      @if (loading()) {
        <p>Loading...</p>
      } @else if (sessionUserId()) {
        <div class="status success">Signed in as {{ sessionUserId() }}</div>
        <div class="buttons" style="margin-top: 16px">
          <button class="secondary" (click)="doLogout()">Sign Out</button>
        </div>
      } @else {
        <div class="field">
          <label>User ID</label>
          <input [value]="userId()" (input)="userId.set($any($event.target).value)" />
        </div>
        <div class="field">
          <label>Username</label>
          <input [value]="username()" (input)="username.set($any($event.target).value)" />
        </div>
        <div class="buttons">
          <passkey-register [userId]="userId()" [username]="username()"
                            (registered)="onRegistered($event)"
                            (error)="onError($event)" #reg>
            <button class="primary" (click)="reg.register()" [disabled]="reg.loading()">
              {{ reg.loading() ? "Registering..." : "Register Passkey" }}
            </button>
          </passkey-register>
          <passkey-login [userId]="userId()"
                         (authenticated)="onAuthenticated($event)"
                         (error)="onError($event)" #login>
            <button class="secondary" (click)="login.login()" [disabled]="login.loading()">
              {{ login.loading() ? "Signing in..." : "Sign In" }}
            </button>
          </passkey-login>
        </div>
        @if (message()) {
          <div [class]="'status ' + messageType()">{{ message() }}</div>
        }
      }
    </div>
  `,
  styles: [`
    .container { max-width: 480px; margin: 40px auto; padding: 0 20px; font-family: system-ui, sans-serif; color: #1a1a1a; }
    h1 { font-size: 1.5rem; margin-bottom: 8px; }
    .subtitle { color: #666; margin-bottom: 24px; font-size: 0.9rem; }
    .field { margin-bottom: 12px; }
    .field label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px; }
    .field input { width: 100%; padding: 8px 12px; border: 1px solid #ccc; border-radius: 6px; font-size: 0.95rem; box-sizing: border-box; }
    .buttons { display: flex; gap: 8px; margin-top: 16px; }
    button { flex: 1; padding: 10px; border: none; border-radius: 6px; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
    .primary { background: #2563eb; color: #fff; }
    .primary:hover:not(:disabled) { background: #1d4ed8; }
    .secondary { background: #e5e7eb; color: #1a1a1a; }
    .secondary:hover:not(:disabled) { background: #d1d5db; }
    button:disabled { opacity: 0.6; cursor: not-allowed; }
    .status { margin-top: 20px; padding: 12px; border-radius: 6px; font-size: 0.9rem; }
    .success { background: #d1fae5; color: #065f46; }
    .error { background: #fee2e2; color: #991b1b; }
  `],
})
export class AppComponent implements OnInit {
  private passkey = inject(PasskeyService);

  userId = signal("test-user");
  username = signal("Test User");
  message = signal("");
  messageType = signal<"success" | "error">("success");
  sessionUserId = signal<string | null>(null);
  loading = signal(true);

  ngOnInit() {
    this.passkey.getSession().subscribe({
      next: (session) => {
        this.sessionUserId.set(session?.userId ?? null);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  onRegistered(result: PasskeyRegistrationResult) {
    this.message.set("Registered! You can now sign in.");
    this.messageType.set("success");
  }

  onAuthenticated(result: PasskeyAuthenticationResult) {
    this.passkey.getSession().subscribe((session) => {
      this.sessionUserId.set(session?.userId ?? null);
    });
  }

  onError(err: Error) {
    this.message.set(err.message || "Something went wrong");
    this.messageType.set("error");
  }

  doLogout() {
    this.passkey.logout().subscribe(() => {
      this.sessionUserId.set(null);
      this.message.set("");
    });
  }
}
