import { inject, Injectable } from "@angular/core";
import { from, Observable } from "rxjs";
import { PasskeyClient } from "@open-passkey/sdk";
import type {
  RegistrationResult,
  AuthenticationResult,
} from "@open-passkey/sdk";
import { PASSKEY_CONFIG } from "./passkey.config";

@Injectable({ providedIn: "root" })
export class PasskeyService {
  private client: PasskeyClient;

  constructor() {
    const config = inject(PASSKEY_CONFIG);
    this.client = new PasskeyClient(config);
  }

  register(
    userId: string,
    username: string,
  ): Observable<RegistrationResult> {
    return from(this.client.register(userId, username));
  }

  authenticate(userId?: string): Observable<AuthenticationResult> {
    return from(this.client.authenticate(userId));
  }
}
