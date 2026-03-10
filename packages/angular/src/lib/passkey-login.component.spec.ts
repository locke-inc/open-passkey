import { ComponentFixture, TestBed } from "@angular/core/testing";
import { Component, viewChild } from "@angular/core";
import { Observable, of, throwError } from "rxjs";
import { PasskeyLoginComponent } from "./passkey-login.component";
import { PasskeyService } from "./passkey.service";
import { PasskeyAuthenticationResult } from "./passkey.types";

@Component({
  standalone: true,
  imports: [PasskeyLoginComponent],
  template: `
    <passkey-login
      [userId]="userId"
      (authenticated)="onAuth($event)"
      (error)="onError($event)"
      #login
    >
      <button class="login-btn" (click)="login.login()">Sign in</button>
    </passkey-login>
  `,
})
class TestHostComponent {
  userId = "user-1";
  authResult: PasskeyAuthenticationResult | null = null;
  errorResult: Error | null = null;
  login = viewChild.required(PasskeyLoginComponent);

  onAuth(result: PasskeyAuthenticationResult) {
    this.authResult = result;
  }
  onError(err: Error) {
    this.errorResult = err;
  }
}

// Separate host for discoverable (no userId) flow
@Component({
  standalone: true,
  imports: [PasskeyLoginComponent],
  template: `
    <passkey-login
      (authenticated)="onAuth($event)"
      #login
    >
      <button (click)="login.login()">Sign in</button>
    </passkey-login>
  `,
})
class DiscoverableHostComponent {
  authResult: PasskeyAuthenticationResult | null = null;
  login = viewChild.required(PasskeyLoginComponent);

  onAuth(result: PasskeyAuthenticationResult) {
    this.authResult = result;
  }
}

describe("PasskeyLoginComponent", () => {
  let fixture: ComponentFixture<TestHostComponent>;
  let host: TestHostComponent;
  let mockService: jest.Mocked<Pick<PasskeyService, "authenticate">>;

  beforeEach(() => {
    mockService = { authenticate: jest.fn() };

    TestBed.configureTestingModule({
      imports: [TestHostComponent],
      providers: [
        { provide: PasskeyService, useValue: mockService },
      ],
    });

    fixture = TestBed.createComponent(TestHostComponent);
    host = fixture.componentInstance;
    fixture.detectChanges();
  });

  it("should project content (the button)", () => {
    const button = fixture.nativeElement.querySelector(".login-btn");
    expect(button).toBeTruthy();
    expect(button.textContent).toContain("Sign in");
  });

  it("should call PasskeyService.authenticate with userId", () => {
    mockService.authenticate.mockReturnValue(
      of({ userId: "user-1", authenticated: true }),
    );

    host.login().login();

    expect(mockService.authenticate).toHaveBeenCalledWith("user-1");
  });

  it("should emit authenticated output on success", () => {
    mockService.authenticate.mockReturnValue(
      of({ userId: "user-1", authenticated: true }),
    );

    host.login().login();
    fixture.detectChanges();

    expect(host.authResult).toEqual({
      userId: "user-1",
      authenticated: true,
    });
  });

  it("should emit error output on failure", () => {
    mockService.authenticate.mockReturnValue(
      throwError(() => new Error("Ceremony failed")),
    );

    host.login().login();
    fixture.detectChanges();

    expect(host.errorResult?.message).toBe("Ceremony failed");
  });

  it("should set loading signal during ceremony", () => {
    const login = host.login();
    expect(login.loading()).toBe(false);

    mockService.authenticate.mockReturnValue(
      of({ userId: "user-1", authenticated: true }),
    );
    login.login();

    expect(login.loading()).toBe(false);
  });

  it("should prevent double-click during loading", () => {
    // Return an observable that never completes synchronously
    mockService.authenticate.mockReturnValue(
      new Observable<PasskeyAuthenticationResult>(() => {
        // intentionally never completes
      }),
    );

    const login = host.login();
    login.login();
    expect(login.loading()).toBe(true);

    login.login();
    expect(mockService.authenticate).toHaveBeenCalledTimes(1);
  });
});

describe("PasskeyLoginComponent (discoverable)", () => {
  let fixture: ComponentFixture<DiscoverableHostComponent>;
  let host: DiscoverableHostComponent;
  let mockService: jest.Mocked<Pick<PasskeyService, "authenticate">>;

  beforeEach(() => {
    mockService = { authenticate: jest.fn() };

    TestBed.configureTestingModule({
      imports: [DiscoverableHostComponent],
      providers: [
        { provide: PasskeyService, useValue: mockService },
      ],
    });

    fixture = TestBed.createComponent(DiscoverableHostComponent);
    host = fixture.componentInstance;
    fixture.detectChanges();
  });

  it("should call authenticate with undefined userId for discoverable credentials", () => {
    mockService.authenticate.mockReturnValue(
      of({ userId: "discovered-user", authenticated: true }),
    );

    host.login().login();

    expect(mockService.authenticate).toHaveBeenCalledWith(undefined);
  });
});
