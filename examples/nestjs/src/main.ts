import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { Module } from "@nestjs/common";
import { PasskeyModule, MemoryChallengeStore, MemoryCredentialStore } from "@open-passkey/nestjs";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

@Module({
  imports: [
    PasskeyModule.forRoot({
      rpId: "localhost",
      rpDisplayName: "Open Passkey NestJS Example",
      origin: "http://localhost:3009",
      challengeStore: new MemoryChallengeStore(),
      credentialStore: new MemoryCredentialStore(),
    }),
  ],
})
class AppModule {}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const httpAdapter = app.getHttpAdapter().getInstance();
  httpAdapter.use(express.static(path.join(__dirname, "../public")));
  httpAdapter.use(express.static(path.join(__dirname, "../../shared")));
  await app.listen(3009);
  console.log("NestJS example running on http://localhost:3009");
}
bootstrap();
