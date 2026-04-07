import { bootstrapApplication } from "@angular/platform-browser";
import { AppComponent } from "./app/app.component";
import { provideHttpClient } from "@angular/common/http";
import { providePasskey } from "@open-passkey/angular";

bootstrapApplication(AppComponent, {
  providers: [
    provideHttpClient(),
    providePasskey({ provider: "locke-gateway", rpId: "localhost" }),
  ],
});
