import { HttpClient } from "@angular/common/http";
import { inject, Injectable } from "@angular/core";
import { Observable, switchMap } from "rxjs";
import { PASSKEY_CONFIG } from "./passkey.config";
import {
  BeginAuthenticationResponse,
  BeginRegistrationResponse,
  FinishAuthenticationRequest,
  FinishRegistrationRequest,
  PasskeyAuthenticationResult,
  PasskeyRegistrationResult,
} from "./passkey.types";
import { base64urlDecode, base64urlEncode } from "./passkey.util";

@Injectable({ providedIn: "root" })
export class PasskeyService {
  private http = inject(HttpClient);
  private config = inject(PASSKEY_CONFIG);

  /**
   * Run the full registration ceremony:
   * 1. POST /register/begin → get creation options
   * 2. Call navigator.credentials.create()
   * 3. POST /register/finish → server verifies and stores credential
   */
  register(
    userId: string,
    username: string,
  ): Observable<PasskeyRegistrationResult> {
    const baseUrl = this.config.baseUrl;

    return this.http
      .post<BeginRegistrationResponse>(`${baseUrl}/register/begin`, {
        userId,
        username,
      })
      .pipe(
        switchMap((options) => this.createCredential(options, userId)),
      );
  }

  /**
   * Run the full authentication ceremony:
   * 1. POST /login/begin → get request options
   * 2. Call navigator.credentials.get()
   * 3. POST /login/finish → server verifies signature
   */
  authenticate(userId?: string): Observable<PasskeyAuthenticationResult> {
    const baseUrl = this.config.baseUrl;

    return this.http
      .post<BeginAuthenticationResponse>(`${baseUrl}/login/begin`, {
        userId,
      })
      .pipe(
        switchMap((options) => this.getCredential(options, userId)),
      );
  }

  private createCredential(
    options: BeginRegistrationResponse,
    userId: string,
  ): Observable<PasskeyRegistrationResult> {
    return new Observable((subscriber) => {
      const publicKey: PublicKeyCredentialCreationOptions = {
        challenge: base64urlDecode(options.challenge),
        rp: options.rp,
        user: {
          id: base64urlDecode(options.user.id),
          name: options.user.name,
          displayName: options.user.displayName,
        },
        pubKeyCredParams: options.pubKeyCredParams.map((p) => ({
          type: p.type as PublicKeyCredentialType,
          alg: p.alg,
        })),
        authenticatorSelection: {
          residentKey: options.authenticatorSelection
            .residentKey as ResidentKeyRequirement,
          userVerification: options.authenticatorSelection
            .userVerification as UserVerificationRequirement,
        },
        timeout: options.timeout,
        attestation: options.attestation as AttestationConveyancePreference,
      };

      navigator.credentials
        .create({ publicKey })
        .then((credential) => {
          if (!credential) {
            subscriber.error(new Error("No credential returned"));
            return;
          }

          const pkc = credential as PublicKeyCredential;
          const response =
            pkc.response as AuthenticatorAttestationResponse;

          const body: FinishRegistrationRequest = {
            userId,
            credential: {
              id: pkc.id,
              rawId: base64urlEncode(pkc.rawId),
              type: pkc.type,
              response: {
                clientDataJSON: base64urlEncode(response.clientDataJSON),
                attestationObject: base64urlEncode(
                  response.attestationObject,
                ),
              },
            },
          };

          this.http
            .post<PasskeyRegistrationResult>(
              `${this.config.baseUrl}/register/finish`,
              body,
            )
            .subscribe({
              next: (result) => {
                subscriber.next(result);
                subscriber.complete();
              },
              error: (err) => subscriber.error(err),
            });
        })
        .catch((err) => subscriber.error(err));
    });
  }

  private getCredential(
    options: BeginAuthenticationResponse,
    userId?: string,
  ): Observable<PasskeyAuthenticationResult> {
    return new Observable((subscriber) => {
      const publicKey: PublicKeyCredentialRequestOptions = {
        challenge: base64urlDecode(options.challenge),
        rpId: options.rpId,
        timeout: options.timeout,
        userVerification:
          options.userVerification as UserVerificationRequirement,
        allowCredentials: options.allowCredentials?.map((c) => ({
          type: c.type as PublicKeyCredentialType,
          id: base64urlDecode(c.id),
        })),
      };

      navigator.credentials
        .get({ publicKey })
        .then((credential) => {
          if (!credential) {
            subscriber.error(new Error("No credential returned"));
            return;
          }

          const pkc = credential as PublicKeyCredential;
          const response =
            pkc.response as AuthenticatorAssertionResponse;

          const body: FinishAuthenticationRequest = {
            userId: userId ?? "",
            credential: {
              id: pkc.id,
              rawId: base64urlEncode(pkc.rawId),
              type: pkc.type,
              response: {
                clientDataJSON: base64urlEncode(response.clientDataJSON),
                authenticatorData: base64urlEncode(
                  response.authenticatorData,
                ),
                signature: base64urlEncode(response.signature),
              },
            },
          };

          this.http
            .post<PasskeyAuthenticationResult>(
              `${this.config.baseUrl}/login/finish`,
              body,
            )
            .subscribe({
              next: (result) => {
                subscriber.next(result);
                subscriber.complete();
              },
              error: (err) => subscriber.error(err),
            });
        })
        .catch((err) => subscriber.error(err));
    });
  }
}
