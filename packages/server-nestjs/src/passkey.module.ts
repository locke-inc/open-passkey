import { Module, type DynamicModule } from "@nestjs/common";
import type { PasskeyConfig } from "@open-passkey/server";
import { PasskeyController } from "./passkey.controller.js";
import { PasskeyService } from "./passkey.service.js";

@Module({})
export class PasskeyModule {
  static forRoot(config: PasskeyConfig): DynamicModule {
    return {
      module: PasskeyModule,
      controllers: [PasskeyController],
      providers: [
        {
          provide: PasskeyService,
          useFactory: () => {
            const service = new PasskeyService();
            service.initialize(config);
            return service;
          },
        },
      ],
      exports: [PasskeyService],
    };
  }
}
