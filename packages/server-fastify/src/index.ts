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
  buildSetCookieHeader,
  buildClearCookieHeader,
  parseCookieToken,
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
      const sessionConfig = passkey.getSessionConfig();
      if (sessionConfig && result.sessionToken) {
        reply.header("Set-Cookie", buildSetCookieHeader(result.sessionToken, sessionConfig));
        const { sessionToken, ...body } = result;
        return reply.send(body);
      }
      return reply.send(result);
    } catch (err) {
      if (err instanceof PasskeyError) {
        return reply.status(err.statusCode).send({ error: err.message });
      }
      return reply.status(500).send({ error: "internal server error" });
    }
  });

  const sessionConfig = passkey.getSessionConfig();
  if (sessionConfig) {
    fastify.get("/session", async (request, reply) => {
      try {
        const token = parseCookieToken(request.headers.cookie as string | undefined, sessionConfig);
        if (!token) {
          return reply.status(401).send({ error: "no session" });
        }
        const data = passkey.getSessionTokenData(token);
        return reply.send({ userId: data.userId, authenticated: true });
      } catch {
        return reply.status(401).send({ error: "invalid session" });
      }
    });

    fastify.post("/logout", async (_request, reply) => {
      reply.header("Set-Cookie", buildClearCookieHeader(sessionConfig));
      return reply.send({ success: true });
    });
  }

  done();
};
