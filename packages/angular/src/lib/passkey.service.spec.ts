import { TestBed, fakeAsync, tick } from "@angular/core/testing";
import {
  HttpTestingController,
  provideHttpClientTesting,
} from "@angular/common/http/testing";
import { provideHttpClient } from "@angular/common/http";
import { PasskeyService } from "./passkey.service";
import { PASSKEY_CONFIG } from "./passkey.config";
import { base64urlEncode } from "./passkey.util";
import {
  BeginRegistrationResponse,
  BeginAuthenticationResponse,
} from "./passkey.types";

// Mock navigator.credentials
const mockCredentials = {
  create: jest.fn(),
  get: jest.fn(),
};

Object.defineProperty(globalThis, "navigator", {
  value: { credentials: mockCredentials },
  writable: true,
});

describe("PasskeyService", () => {
  let service: PasskeyService;
  let httpTesting: HttpTestingController;

  const config = { baseUrl: "/passkey" };

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: PASSKEY_CONFIG, useValue: config },
        PasskeyService,
      ],
    });
    service = TestBed.inject(PasskeyService);
    httpTesting = TestBed.inject(HttpTestingController);
    jest.clearAllMocks();
  });

  afterEach(() => {
    httpTesting.verify();
  });

  describe("register", () => {
    const beginResponse: BeginRegistrationResponse = {
      challenge: base64urlEncode(
        new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer,
      ),
      rp: { id: "example.com", name: "Example" },
      user: {
        id: base64urlEncode(new Uint8Array([10, 20]).buffer),
        name: "alice",
        displayName: "Alice",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      timeout: 60000,
      attestation: "none",
    };

    function mockWebAuthnCreate(prfEnabled = false): void {
      const rawId = new Uint8Array([100, 101, 102]).buffer;
      const clientDataJSON = new Uint8Array([1, 2, 3]).buffer;
      const attestationObject = new Uint8Array([4, 5, 6]).buffer;
      const prfOutput = new Uint8Array([99, 98, 97]).buffer;
      mockCredentials.create.mockResolvedValue({
        id: "credential-id",
        rawId,
        type: "public-key",
        response: { clientDataJSON, attestationObject },
        getClientExtensionResults: () =>
          prfEnabled
            ? { prf: { enabled: true, results: { first: prfOutput } } }
            : {},
      });
    }

    it("should POST to /register/begin then call navigator.credentials.create", fakeAsync(() => {
      mockWebAuthnCreate();
      service.register("user-1", "alice").subscribe();

      const beginReq = httpTesting.expectOne("/passkey/register/begin");
      expect(beginReq.request.method).toBe("POST");
      expect(beginReq.request.body).toEqual({
        userId: "user-1",
        username: "alice",
      });
      beginReq.flush(beginResponse);

      // Flush the microtask from navigator.credentials.create (resolved promise)
      tick();

      expect(mockCredentials.create).toHaveBeenCalledTimes(1);
      const createArg = mockCredentials.create.mock.calls[0][0];
      expect(createArg.publicKey.rp.id).toBe("example.com");
      expect(createArg.publicKey.timeout).toBe(60000);

      const finishReq = httpTesting.expectOne("/passkey/register/finish");
      expect(finishReq.request.method).toBe("POST");
      expect(finishReq.request.body.userId).toBe("user-1");
      expect(finishReq.request.body.credential.id).toBe("credential-id");
      expect(finishReq.request.body.credential.type).toBe("public-key");
      finishReq.flush({ credentialId: "credential-id", registered: true });
    }));

    it("should emit the registration result on success", fakeAsync(() => {
      mockWebAuthnCreate();
      let result: any;
      service.register("user-1", "alice").subscribe((r) => (result = r));

      httpTesting.expectOne("/passkey/register/begin").flush(beginResponse);
      tick();
      httpTesting
        .expectOne("/passkey/register/finish")
        .flush({ credentialId: "credential-id", registered: true });

      expect(result).toEqual({
        credentialId: "credential-id",
        registered: true,
      });
    }));

    it("should emit error if navigator.credentials.create fails", fakeAsync(() => {
      mockCredentials.create.mockRejectedValue(
        new Error("User cancelled"),
      );
      let error: any;
      service.register("user-1", "alice").subscribe({
        error: (err) => (error = err),
      });

      httpTesting.expectOne("/passkey/register/begin").flush(beginResponse);
      tick();

      expect(error.message).toBe("User cancelled");
    }));

    it("should emit error if navigator.credentials.create returns null", fakeAsync(() => {
      mockCredentials.create.mockResolvedValue(null);
      let error: any;
      service.register("user-1", "alice").subscribe({
        error: (err) => (error = err),
      });

      httpTesting.expectOne("/passkey/register/begin").flush(beginResponse);
      tick();

      expect(error.message).toBe("No credential returned");
    }));

    it("should emit error if /register/begin fails", fakeAsync(() => {
      let error: any;
      service.register("user-1", "alice").subscribe({
        error: (err) => (error = err),
      });

      httpTesting
        .expectOne("/passkey/register/begin")
        .flush("Server error", {
          status: 500,
          statusText: "Internal Server Error",
        });

      expect(error).toBeTruthy();
    }));

    it("should base64url-encode credential response fields", fakeAsync(() => {
      mockWebAuthnCreate();
      service.register("user-1", "alice").subscribe();

      httpTesting.expectOne("/passkey/register/begin").flush(beginResponse);
      tick();

      const finishReq = httpTesting.expectOne("/passkey/register/finish");
      const body = finishReq.request.body;
      // rawId [100,101,102] -> base64url "ZGVm"
      expect(body.credential.rawId).toBe("ZGVm");
      // clientDataJSON [1,2,3] -> base64url "AQID"
      expect(body.credential.response.clientDataJSON).toBe("AQID");
      // attestationObject [4,5,6] -> base64url "BAUG"
      expect(body.credential.response.attestationObject).toBe("BAUG");
      finishReq.flush({ credentialId: "credential-id", registered: true });
    }));

    it("should pass PRF eval extension through create() when present", fakeAsync(() => {
      mockWebAuthnCreate();
      const beginWithPrf: BeginRegistrationResponse = {
        ...beginResponse,
        extensions: {
          prf: { eval: { first: "AQIDBA" } },  // base64url of [1,2,3,4]
        },
      };
      service.register("user-1", "alice").subscribe();

      httpTesting.expectOne("/passkey/register/begin").flush(beginWithPrf);
      tick();

      const createArg = mockCredentials.create.mock.calls[0][0];
      expect(createArg.publicKey.extensions).toBeDefined();
      expect(createArg.publicKey.extensions.prf).toBeDefined();
      expect(createArg.publicKey.extensions.prf.eval.first).toBeInstanceOf(ArrayBuffer);

      const finishReq = httpTesting.expectOne("/passkey/register/finish");
      expect(finishReq.request.body.prfSupported).toBe(false);
      finishReq.flush({ credentialId: "credential-id", registered: true, prfSupported: false });
    }));

    it("should report prfSupported=true and include prfOutput when authenticator supports PRF", fakeAsync(() => {
      mockWebAuthnCreate(true);
      const beginWithPrf: BeginRegistrationResponse = {
        ...beginResponse,
        extensions: {
          prf: { eval: { first: "AQIDBA" } },
        },
      };
      let result: any;
      service.register("user-1", "alice").subscribe((r) => (result = r));

      httpTesting.expectOne("/passkey/register/begin").flush(beginWithPrf);
      tick();

      const finishReq = httpTesting.expectOne("/passkey/register/finish");
      expect(finishReq.request.body.prfSupported).toBe(true);
      finishReq.flush({ credentialId: "credential-id", registered: true, prfSupported: true });

      expect(result.prfSupported).toBe(true);
      expect(result.prfOutput).toBeInstanceOf(ArrayBuffer);
    }));

    it("should not include extensions when server response has no PRF", fakeAsync(() => {
      mockWebAuthnCreate();
      service.register("user-1", "alice").subscribe();

      httpTesting.expectOne("/passkey/register/begin").flush(beginResponse);
      tick();

      const createArg = mockCredentials.create.mock.calls[0][0];
      expect(createArg.publicKey.extensions).toBeUndefined();

      const finishReq = httpTesting.expectOne("/passkey/register/finish");
      finishReq.flush({ credentialId: "credential-id", registered: true, prfSupported: false });
    }));
  });

  describe("authenticate", () => {
    const beginResponse: BeginAuthenticationResponse = {
      challenge: base64urlEncode(
        new Uint8Array([10, 20, 30, 40]).buffer,
      ),
      rpId: "example.com",
      timeout: 60000,
      userVerification: "preferred",
      allowCredentials: [{ type: "public-key", id: "cred-abc" }],
    };

    function mockWebAuthnGet(withPrf = false): void {
      const rawId = new Uint8Array([200, 201]).buffer;
      const clientDataJSON = new Uint8Array([7, 8]).buffer;
      const authenticatorData = new Uint8Array([9, 10]).buffer;
      const signature = new Uint8Array([11, 12]).buffer;
      const prfOutput = new Uint8Array([50, 51, 52]).buffer;
      mockCredentials.get.mockResolvedValue({
        id: "cred-abc",
        rawId,
        type: "public-key",
        response: { clientDataJSON, authenticatorData, signature },
        getClientExtensionResults: () =>
          withPrf
            ? { prf: { results: { first: prfOutput } } }
            : {},
      });
    }

    it("should POST to /login/begin then call navigator.credentials.get", fakeAsync(() => {
      mockWebAuthnGet();
      service.authenticate("user-1").subscribe();

      const beginReq = httpTesting.expectOne("/passkey/login/begin");
      expect(beginReq.request.method).toBe("POST");
      expect(beginReq.request.body).toEqual({ userId: "user-1" });
      beginReq.flush(beginResponse);

      tick();

      expect(mockCredentials.get).toHaveBeenCalledTimes(1);
      const getArg = mockCredentials.get.mock.calls[0][0];
      expect(getArg.publicKey.rpId).toBe("example.com");

      const finishReq = httpTesting.expectOne("/passkey/login/finish");
      expect(finishReq.request.method).toBe("POST");
      expect(finishReq.request.body.userId).toBe("user-1");
      expect(finishReq.request.body.credential.id).toBe("cred-abc");
      finishReq.flush({ userId: "user-1", authenticated: true });
    }));

    it("should emit the authentication result on success", fakeAsync(() => {
      mockWebAuthnGet();
      let result: any;
      service.authenticate("user-1").subscribe((r) => (result = r));

      httpTesting.expectOne("/passkey/login/begin").flush(beginResponse);
      tick();
      httpTesting
        .expectOne("/passkey/login/finish")
        .flush({ userId: "user-1", authenticated: true });

      expect(result).toEqual({
        userId: "user-1",
        authenticated: true,
      });
    }));

    it("should support discoverable credentials (no userId)", fakeAsync(() => {
      mockWebAuthnGet();
      service.authenticate().subscribe();

      const beginReq = httpTesting.expectOne("/passkey/login/begin");
      expect(beginReq.request.body).toEqual({ userId: undefined });
      beginReq.flush(beginResponse);

      tick();

      const finishReq = httpTesting.expectOne("/passkey/login/finish");
      expect(finishReq.request.body.userId).toBe("");
      finishReq.flush({ userId: "user-1", authenticated: true });
    }));

    it("should emit error if navigator.credentials.get fails", fakeAsync(() => {
      mockCredentials.get.mockRejectedValue(new Error("Aborted"));
      let error: any;
      service.authenticate("user-1").subscribe({
        error: (err) => (error = err),
      });

      httpTesting.expectOne("/passkey/login/begin").flush(beginResponse);
      tick();

      expect(error.message).toBe("Aborted");
    }));

    it("should base64url-encode assertion response fields", fakeAsync(() => {
      mockWebAuthnGet();
      service.authenticate("user-1").subscribe();

      httpTesting.expectOne("/passkey/login/begin").flush(beginResponse);
      tick();

      const finishReq = httpTesting.expectOne("/passkey/login/finish");
      const body = finishReq.request.body;
      // rawId [200,201] -> base64url "yMk"
      expect(body.credential.rawId).toBe("yMk");
      // signature [11,12] -> base64url "Cww"
      expect(body.credential.response.signature).toBe("Cww");
      finishReq.flush({ userId: "user-1", authenticated: true });
    }));

    it("should build evalByCredential PRF extension for get()", fakeAsync(() => {
      mockWebAuthnGet();
      const beginWithPrf: BeginAuthenticationResponse = {
        ...beginResponse,
        extensions: {
          prf: {
            evalByCredential: {
              "cred-abc": { first: "AQIDBA" },
              "cred-def": { first: "BQYHCA" },
            },
          },
        },
      };
      service.authenticate("user-1").subscribe();

      httpTesting.expectOne("/passkey/login/begin").flush(beginWithPrf);
      tick();

      const getArg = mockCredentials.get.mock.calls[0][0];
      expect(getArg.publicKey.extensions).toBeDefined();
      expect(getArg.publicKey.extensions.prf.evalByCredential).toBeDefined();
      expect(getArg.publicKey.extensions.prf.evalByCredential["cred-abc"].first).toBeInstanceOf(ArrayBuffer);
      expect(getArg.publicKey.extensions.prf.evalByCredential["cred-def"].first).toBeInstanceOf(ArrayBuffer);

      httpTesting.expectOne("/passkey/login/finish").flush({ userId: "user-1", authenticated: true });
    }));

    it("should fall back to eval when evalByCredential is absent", fakeAsync(() => {
      mockWebAuthnGet();
      const beginWithEval: BeginAuthenticationResponse = {
        ...beginResponse,
        extensions: {
          prf: {
            eval: { first: "AQIDBA" },
          },
        },
      };
      service.authenticate("user-1").subscribe();

      httpTesting.expectOne("/passkey/login/begin").flush(beginWithEval);
      tick();

      const getArg = mockCredentials.get.mock.calls[0][0];
      expect(getArg.publicKey.extensions.prf.eval.first).toBeInstanceOf(ArrayBuffer);
      expect(getArg.publicKey.extensions.prf.evalByCredential).toBeUndefined();

      httpTesting.expectOne("/passkey/login/finish").flush({ userId: "user-1", authenticated: true });
    }));

    it("should extract prfOutput from extension results during authentication", fakeAsync(() => {
      mockWebAuthnGet(true);
      let result: any;
      service.authenticate("user-1").subscribe((r) => (result = r));

      httpTesting.expectOne("/passkey/login/begin").flush(beginResponse);
      tick();
      httpTesting.expectOne("/passkey/login/finish").flush({ userId: "user-1", authenticated: true, prfSupported: true });

      expect(result.prfOutput).toBeInstanceOf(ArrayBuffer);
      expect(result.prfSupported).toBe(true);
    }));

    it("should not include extensions when server response has no PRF", fakeAsync(() => {
      mockWebAuthnGet();
      service.authenticate("user-1").subscribe();

      httpTesting.expectOne("/passkey/login/begin").flush(beginResponse);
      tick();

      const getArg = mockCredentials.get.mock.calls[0][0];
      expect(getArg.publicKey.extensions).toBeUndefined();

      httpTesting.expectOne("/passkey/login/finish").flush({ userId: "user-1", authenticated: true });
    }));
  });
});
