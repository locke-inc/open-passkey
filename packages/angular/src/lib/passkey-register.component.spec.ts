import { ComponentFixture, TestBed } from "@angular/core/testing";
import { Component, viewChild } from "@angular/core";
import { Observable, of, throwError } from "rxjs";
import { PasskeyRegisterComponent } from "./passkey-register.component";
import { PasskeyService } from "./passkey.service";
import { PasskeyRegistrationResult } from "./passkey.types";

// Host component to test content projection and template ref
@Component({
  standalone: true,
  imports: [PasskeyRegisterComponent],
  template: `
    <passkey-register
      [userId]="userId"
      [username]="username"
      (registered)="onRegistered($event)"
      (error)="onError($event)"
      #reg
    >
      <button class="register-btn" (click)="reg.register()">Register</button>
    </passkey-register>
  `,
})
class TestHostComponent {
  userId = "user-1";
  username = "alice";
  registeredResult: PasskeyRegistrationResult | null = null;
  errorResult: Error | null = null;
  reg = viewChild.required(PasskeyRegisterComponent);

  onRegistered(result: PasskeyRegistrationResult) {
    this.registeredResult = result;
  }
  onError(err: Error) {
    this.errorResult = err;
  }
}

describe("PasskeyRegisterComponent", () => {
  let fixture: ComponentFixture<TestHostComponent>;
  let host: TestHostComponent;
  let mockService: jest.Mocked<Pick<PasskeyService, "register">>;

  beforeEach(() => {
    mockService = { register: jest.fn() };

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
    const button = fixture.nativeElement.querySelector(".register-btn");
    expect(button).toBeTruthy();
    expect(button.textContent).toContain("Register");
  });

  it("should call PasskeyService.register with userId and username", () => {
    mockService.register.mockReturnValue(
      of({ credentialId: "cid", registered: true }),
    );

    host.reg().register();

    expect(mockService.register).toHaveBeenCalledWith("user-1", "alice");
  });

  it("should emit registered output on success", () => {
    mockService.register.mockReturnValue(
      of({ credentialId: "cid", registered: true }),
    );

    host.reg().register();
    fixture.detectChanges();

    expect(host.registeredResult).toEqual({
      credentialId: "cid",
      registered: true,
    });
  });

  it("should emit error output on failure", () => {
    mockService.register.mockReturnValue(
      throwError(() => new Error("WebAuthn failed")),
    );

    host.reg().register();
    fixture.detectChanges();

    expect(host.errorResult?.message).toBe("WebAuthn failed");
  });

  it("should set loading to true during ceremony and false after", () => {
    const reg = host.reg();
    expect(reg.loading()).toBe(false);

    mockService.register.mockReturnValue(
      of({ credentialId: "cid", registered: true }),
    );
    reg.register();

    // After synchronous completion, loading should be false again
    expect(reg.loading()).toBe(false);
  });

  it("should prevent double-click during loading", () => {
    // Return an observable that never completes synchronously
    mockService.register.mockReturnValue(
      new Observable<PasskeyRegistrationResult>(() => {
        // intentionally never completes
      }),
    );

    const reg = host.reg();
    reg.register();
    expect(reg.loading()).toBe(true);

    // Second call while loading — should be ignored
    reg.register();
    expect(mockService.register).toHaveBeenCalledTimes(1);
  });
});
