import { Controller, Post, Body, HttpException } from "@nestjs/common";
import {
  PasskeyError,
  type BeginRegistrationRequest,
  type FinishRegistrationRequest,
  type BeginAuthenticationRequest,
  type FinishAuthenticationRequest,
} from "@open-passkey/server";
import { PasskeyService } from "./passkey.service.js";

@Controller("passkey")
export class PasskeyController {
  constructor(private readonly passkeyService: PasskeyService) {}

  private async handle(fn: () => Promise<unknown>): Promise<unknown> {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof PasskeyError) {
        throw new HttpException({ error: err.message }, err.statusCode);
      }
      throw new HttpException({ error: "internal server error" }, 500);
    }
  }

  @Post("/register/begin")
  async registerBegin(@Body() body: BeginRegistrationRequest): Promise<unknown> {
    return this.handle(() => this.passkeyService.beginRegistration(body));
  }

  @Post("/register/finish")
  async registerFinish(@Body() body: FinishRegistrationRequest): Promise<unknown> {
    return this.handle(() => this.passkeyService.finishRegistration(body));
  }

  @Post("/login/begin")
  async loginBegin(@Body() body: BeginAuthenticationRequest): Promise<unknown> {
    return this.handle(() => this.passkeyService.beginAuthentication(body));
  }

  @Post("/login/finish")
  async loginFinish(@Body() body: FinishAuthenticationRequest): Promise<unknown> {
    return this.handle(() => this.passkeyService.finishAuthentication(body));
  }
}
