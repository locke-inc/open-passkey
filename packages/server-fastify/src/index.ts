import type { FastifyInstance, FastifyPluginCallback } from "fastify";
import {
  Passkey,
  PasskeyError,
  type PasskeyConfig,
  type BeginRegistrationRequest,
  type FinishRegistrationRequest,
  type BeginAuthenticationRequest,
  type FinishAuthenticationRequest,
  MemoryChallengeStore,
  MemoryCredentialStore,
} from "@open-passkey/server";

export { MemoryChallengeStore, MemoryCredentialStore };
export type { PasskeyConfig };

export const passkeyPlugin: FastifyPluginCallback<PasskeyConfig> = (
  fastify: FastifyInstance,
  config: PasskeyConfig,
  done: (err?: Error) => void,
) => {
  const passkey = new Passkey(config);

  fastify.post("/register/begin", async (request, reply) => {
    try {
      const result = await passkey.beginRegistration(request.body as BeginRegistrationRequest);
      return reply.send(result);
    } catch (err) {
      if (err instanceof PasskeyError) {
        return reply.status(err.statusCode).send({ error: err.message });
      }
      return reply.status(500).send({ error: "internal server error" });
    }
  });

  fastify.post("/register/finish", async (request, reply) => {
    try {
      const result = await passkey.finishRegistration(request.body as FinishRegistrationRequest);
      return reply.send(result);
    } catch (err) {
      if (err instanceof PasskeyError) {
        return reply.status(err.statusCode).send({ error: err.message });
      }
      return reply.status(500).send({ error: "internal server error" });
    }
  });

  fastify.post("/login/begin", async (request, reply) => {
    try {
      const result = await passkey.beginAuthentication(request.body as BeginAuthenticationRequest);
      return reply.send(result);
    } catch (err) {
      if (err instanceof PasskeyError) {
        return reply.status(err.statusCode).send({ error: err.message });
      }
      return reply.status(500).send({ error: "internal server error" });
    }
  });

  fastify.post("/login/finish", async (request, reply) => {
    try {
      const result = await passkey.finishAuthentication(request.body as FinishAuthenticationRequest);
      return reply.send(result);
    } catch (err) {
      if (err instanceof PasskeyError) {
        return reply.status(err.statusCode).send({ error: err.message });
      }
      return reply.status(500).send({ error: "internal server error" });
    }
  });

  done();
};
