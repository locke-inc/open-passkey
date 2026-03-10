import { InjectionToken, Provider } from "@angular/core";
import { PasskeyConfig } from "./passkey.types";

export const PASSKEY_CONFIG = new InjectionToken<PasskeyConfig>(
  "PASSKEY_CONFIG",
);

/**
 * Provide passkey configuration for the application.
 *
 * Usage in app.config.ts:
 *   providePasskey({ baseUrl: '/passkey' })
 */
export function providePasskey(config: PasskeyConfig): Provider[] {
  return [{ provide: PASSKEY_CONFIG, useValue: config }];
}
