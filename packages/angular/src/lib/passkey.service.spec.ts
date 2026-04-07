import { TestBed } from "@angular/core/testing";
import { PasskeyService } from "./passkey.service";
import { PASSKEY_CONFIG } from "./passkey.config";
import { PasskeyClient } from "@open-passkey/sdk";

jest.mock("@open-passkey/sdk", () => {
  return {
    PasskeyClient: jest.fn().mockImplementation(() => ({
      register: jest.fn(),
      authenticate: jest.fn(),
      getSession: jest.fn(),
      logout: jest.fn(),
    })),
  };
});

describe("PasskeyService", () => {
  let service: PasskeyService;
  let mockClient: jest.Mocked<PasskeyClient>;

  const config = { baseUrl: "/passkey" };

  beforeEach(() => {
    jest.clearAllMocks();
    TestBed.configureTestingModule({
      providers: [
        { provide: PASSKEY_CONFIG, useValue: config },
        PasskeyService,
      ],
    });
    service = TestBed.inject(PasskeyService);
    // Access the mocked client instance
    mockClient = (PasskeyClient as jest.Mock).mock.results[0]
      .value as jest.Mocked<PasskeyClient>;
  });

  it("should create PasskeyClient with the configured baseUrl", () => {
    expect(PasskeyClient).toHaveBeenCalledWith({ baseUrl: "/passkey" });
  });

  describe("register", () => {
    it("should delegate to PasskeyClient.register and emit result", (done) => {
      const expected = {
        credentialId: "cred-123",
        registered: true,
        prfSupported: false,
      };
      mockClient.register.mockResolvedValue(expected);

      service.register("user-1", "alice").subscribe({
        next: (result) => {
          expect(result).toEqual(expected);
          expect(mockClient.register).toHaveBeenCalledWith("user-1", "alice");
          done();
        },
        error: done.fail,
      });
    });

    it("should propagate errors from PasskeyClient.register", (done) => {
      mockClient.register.mockRejectedValue(new Error("User cancelled"));

      service.register("user-1", "alice").subscribe({
        next: () => done.fail("should not emit"),
        error: (err) => {
          expect(err.message).toBe("User cancelled");
          done();
        },
      });
    });
  });

  describe("authenticate", () => {
    it("should delegate to PasskeyClient.authenticate and emit result", (done) => {
      const expected = { userId: "user-1", authenticated: true };
      mockClient.authenticate.mockResolvedValue(expected);

      service.authenticate("user-1").subscribe({
        next: (result) => {
          expect(result).toEqual(expected);
          expect(mockClient.authenticate).toHaveBeenCalledWith("user-1");
          done();
        },
        error: done.fail,
      });
    });

    it("should support discoverable credentials (no userId)", (done) => {
      const expected = { userId: "user-1", authenticated: true };
      mockClient.authenticate.mockResolvedValue(expected);

      service.authenticate().subscribe({
        next: (result) => {
          expect(result).toEqual(expected);
          expect(mockClient.authenticate).toHaveBeenCalledWith(undefined);
          done();
        },
        error: done.fail,
      });
    });

    it("should propagate errors from PasskeyClient.authenticate", (done) => {
      mockClient.authenticate.mockRejectedValue(new Error("Aborted"));

      service.authenticate("user-1").subscribe({
        next: () => done.fail("should not emit"),
        error: (err) => {
          expect(err.message).toBe("Aborted");
          done();
        },
      });
    });
  });

  describe("getSession", () => {
    it("should delegate to PasskeyClient.getSession()", (done) => {
      const expected = { userId: "user-1", authenticated: true };
      mockClient.getSession.mockResolvedValue(expected);

      service.getSession().subscribe({
        next: (result) => {
          expect(result).toEqual(expected);
          expect(mockClient.getSession).toHaveBeenCalled();
          done();
        },
        error: done.fail,
      });
    });

    it("should return null when no session", (done) => {
      mockClient.getSession.mockResolvedValue(null);

      service.getSession().subscribe({
        next: (result) => {
          expect(result).toBeNull();
          done();
        },
        error: done.fail,
      });
    });
  });

  describe("logout", () => {
    it("should delegate to PasskeyClient.logout()", (done) => {
      mockClient.logout.mockResolvedValue(undefined);

      service.logout().subscribe({
        next: () => {
          expect(mockClient.logout).toHaveBeenCalled();
          done();
        },
        error: done.fail,
      });
    });
  });
});
