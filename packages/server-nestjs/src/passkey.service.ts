import { Injectable } from "@nestjs/common";
import {
  Passkey,
  type PasskeyConfig,
  type BeginRegistrationRequest,
  type FinishRegistrationRequest,
  type BeginAuthenticationRequest,
  type FinishAuthenticationRequest,
} from "@open-passkey/server";

@Injectable()
export class PasskeyService {
  private passkey!: Passkey;

  initialize(config: PasskeyConfig): void {
    this.passkey = new Passkey(config);
  }

  async beginRegistration(body: BeginRegistrationRequest): Promise<unknown> {
    return this.passkey.beginRegistration(body);
  }

  async finishRegistration(body: FinishRegistrationRequest): Promise<unknown> {
    return this.passkey.finishRegistration(body);
  }

  async beginAuthentication(body: BeginAuthenticationRequest): Promise<unknown> {
    return this.passkey.beginAuthentication(body);
  }

  async finishAuthentication(body: FinishAuthenticationRequest): Promise<unknown> {
    return this.passkey.finishAuthentication(body);
  }

  getSessionTokenData(token: string) {
    return this.passkey.getSessionTokenData(token);
  }

  getSessionConfig() {
    return this.passkey.getSessionConfig();
  }
}
