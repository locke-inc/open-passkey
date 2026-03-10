import { Component, inject, input, output, signal } from "@angular/core";
import { PasskeyService } from "./passkey.service";
import { PasskeyAuthenticationResult } from "./passkey.types";

/**
 * Headless passkey login component.
 *
 * Provides the authentication ceremony logic with no rendered UI.
 * Use content projection to supply your own button/form.
 *
 * Usage:
 *   <passkey-login [userId]="uid"
 *                  (authenticated)="onSuccess($event)"
 *                  (error)="onError($event)" #login>
 *     <button (click)="login.login()" [disabled]="login.loading()">
 *       Sign in with Passkey
 *     </button>
 *   </passkey-login>
 */
@Component({
  selector: "passkey-login",
  standalone: true,
  template: "<ng-content />",
})
export class PasskeyLoginComponent {
  private passkey = inject(PasskeyService);

  userId = input<string>();

  authenticated = output<PasskeyAuthenticationResult>();
  error = output<Error>();

  loading = signal(false);

  login(): void {
    if (this.loading()) return;
    this.loading.set(true);

    this.passkey.authenticate(this.userId()).subscribe({
      next: (result) => {
        this.loading.set(false);
        this.authenticated.emit(result);
      },
      error: (err) => {
        this.loading.set(false);
        this.error.emit(err);
      },
    });
  }
}
