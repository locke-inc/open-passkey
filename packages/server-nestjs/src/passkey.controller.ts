import { Controller, Post, Get, Body, Req, Res, Headers, HttpException } from "@nestjs/common";
import {
  PasskeyError,
  buildSetCookieHeader,
  buildClearCookieHeader,
  parseCookieToken,
  type BeginRegistrationRequest,
  type FinishRegistrationRequest,
  type BeginAuthenticationRequest,
  type FinishAuthenticationRequest,
} from "@open-passkey/server";
import type { Response } from "express";
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
  async registerFinish(
    @Body() body: FinishRegistrationRequest,
    @Res({ passthrough: true }) res: Response,
  ): Promise<unknown> {
    try {
      const result = await this.passkeyService.finishRegistration(body);
      const sessionConfig = this.passkeyService.getSessionConfig();
      if (sessionConfig && (result as any).sessionToken) {
        const { sessionToken: _, ...responseBody } = result as any;
        res.setHeader("Set-Cookie", buildSetCookieHeader(_, sessionConfig));
        return responseBody;
      }
      return result;
    } catch (err) {
      if (err instanceof PasskeyError) {
        throw new HttpException({ error: err.message }, err.statusCode);
      }
      throw new HttpException({ error: "internal server error" }, 500);
    }
  }

  @Post("/login/begin")
  async loginBegin(@Body() body: BeginAuthenticationRequest): Promise<unknown> {
    return this.handle(() => this.passkeyService.beginAuthentication(body));
  }

  @Post("/login/finish")
  async loginFinish(
    @Body() body: FinishAuthenticationRequest,
    @Res({ passthrough: true }) res: Response,
  ): Promise<unknown> {
    try {
      const result = await this.passkeyService.finishAuthentication(body);
      const sessionConfig = this.passkeyService.getSessionConfig();
      if (sessionConfig && (result as any).sessionToken) {
        const { sessionToken: _, ...responseBody } = result as any;
        res.setHeader("Set-Cookie", buildSetCookieHeader(_, sessionConfig));
        return responseBody;
      }
      return result;
    } catch (err) {
      if (err instanceof PasskeyError) {
        throw new HttpException({ error: err.message }, err.statusCode);
      }
      throw new HttpException({ error: "internal server error" }, 500);
    }
  }

  @Get("/session")
  async getSession(@Headers("cookie") cookie: string): Promise<unknown> {
    const sessionConfig = this.passkeyService.getSessionConfig();
    if (!sessionConfig) {
      throw new HttpException({ error: "session not enabled" }, 404);
    }
    try {
      const token = parseCookieToken(cookie, sessionConfig);
      if (!token) {
        throw new HttpException({ error: "no session" }, 401);
      }
      const data = this.passkeyService.getSessionTokenData(token);
      return { userId: data.userId, authenticated: true };
    } catch (err) {
      if (err instanceof HttpException) throw err;
      throw new HttpException({ error: "invalid session" }, 401);
    }
  }

  @Post("/logout")
  async logout(@Res({ passthrough: true }) res: Response): Promise<unknown> {
    const sessionConfig = this.passkeyService.getSessionConfig();
    if (sessionConfig) {
      res.setHeader("Set-Cookie", buildClearCookieHeader(sessionConfig));
    }
    return { success: true };
  }
}
