import { Component, inject, input, output, signal } from "@angular/core";
import { PasskeyService } from "./passkey.service";
import { PasskeyRegistrationResult } from "./passkey.types";

/**
 * Headless passkey registration component.
 *
 * Provides the registration ceremony logic with no rendered UI.
 * Use content projection to supply your own button/form.
 *
 * Usage:
 *   <passkey-register [userId]="uid" [username]="name"
 *                     (registered)="onSuccess($event)"
 *                     (error)="onError($event)" #reg>
 *     <button (click)="reg.register()" [disabled]="reg.loading()">
 *       Register Passkey
 *     </button>
 *   </passkey-register>
 */
@Component({
  selector: "passkey-register",
  standalone: true,
  template: "<ng-content />",
})
export class PasskeyRegisterComponent {
  private passkey = inject(PasskeyService);

  userId = input.required<string>();
  username = input.required<string>();

  registered = output<PasskeyRegistrationResult>();
  error = output<Error>();

  loading = signal(false);

  register(): void {
    if (this.loading()) return;
    this.loading.set(true);

    this.passkey.register(this.userId(), this.username()).subscribe({
      next: (result) => {
        this.loading.set(false);
        this.registered.emit(result);
      },
      error: (err) => {
        this.loading.set(false);
        this.error.emit(err);
      },
    });
  }
}
