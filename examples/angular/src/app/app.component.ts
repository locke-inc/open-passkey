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
    <div class="page">
      <div class="card">
        <h1>open-passkey</h1>
        <p class="subtitle">Angular Example</p>

        @if (loading()) {
          <div class="loading">Loading...</div>
        } @else if (sessionUserId()) {
          <div class="signed-in">
            <div class="signed-in-badge">Authenticated</div>
            <div class="signed-in-email">{{ sessionUserId() }}</div>
            <button class="btn-secondary" (click)="doLogout()">Sign Out</button>
          </div>
        } @else {
          <div class="field">
            <label for="email">Email</label>
            <input
              id="email"
              type="email"
              placeholder="you@example.com"
              [value]="email()"
              (input)="email.set($any($event.target).value)"
            />
          </div>
          <div class="actions">
            <passkey-register
              [userId]="email()"
              [username]="email()"
              (registered)="onRegistered($event)"
              (error)="onError($event)"
              #reg
            >
              <button
                class="btn-primary"
                (click)="reg.register()"
                [disabled]="!email() || reg.loading()"
              >
                {{ reg.loading() ? 'Creating...' : 'Create Passkey' }}
              </button>
            </passkey-register>

            <div class="divider"><span>or</span></div>

            <passkey-login
              [userId]="email()"
              (authenticated)="onAuthenticated($event)"
              (error)="onError($event)"
              #login
            >
              <button
                class="btn-secondary"
                (click)="login.login()"
                [disabled]="login.loading()"
              >
                {{ login.loading() ? 'Signing in...' : 'Sign in with Passkey' }}
              </button>
            </passkey-login>
          </div>
          @if (message()) {
            <div [class]="'status ' + messageType()">{{ message() }}</div>
          }
        }
      </div>
    </div>
  `,
  styles: [`
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

    .field input::placeholder {
      color: #9ca3af;
    }

    .actions {
      display: flex;
      flex-direction: column;
    }

    /* Primary CTA — Teal with animated border on hover */
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

    .btn-primary:hover:not(:disabled) {
      background: transparent;
      color: #0e7490;
    }

    .btn-primary:hover:not(:disabled)::before {
      opacity: 1;
    }

    .btn-primary:active:not(:disabled) {
      transform: scale(0.98);
    }

    /* Secondary CTA — Dark with animated border on hover */
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

    .btn-secondary:hover:not(:disabled) {
      background: transparent;
      color: #1f2937;
    }

    .btn-secondary:hover:not(:disabled)::before {
      opacity: 1;
    }

    .btn-secondary:active:not(:disabled) {
      transform: scale(0.98);
    }

    .btn-primary:disabled,
    .btn-secondary:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

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

    .status {
      margin-top: 20px;
      padding: 12px 16px;
      border-radius: 10px;
      font-size: 0.875rem;
      line-height: 1.4;
    }

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

    .signed-in {
      text-align: center;
    }

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
  `],
})
export class AppComponent implements OnInit {
  private passkey = inject(PasskeyService);

  email = signal("");
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
    this.passkey.getSession().subscribe((session) => {
      this.sessionUserId.set(session?.userId ?? null);
    });
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
