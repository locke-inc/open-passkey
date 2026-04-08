# Add Session Support to All Framework Examples

## All Steps Complete

- [x] **Step 0**: Auto-login after registration — `finishRegistration()` creates session token in all 6 server packages + all 12 framework bindings set cookie
- [x] **Step 1**: TS full-stack examples (Nuxt, SvelteKit, Remix, Astro) — config + session/logout route files created
- [x] **Step 2**: TS server-only examples (Express, Fastify, Hono, NestJS) — session config added
- [x] **Step 3**: Go examples (nethttp, echo, chi, gin, fiber) — session config + routes added
- [x] **Step 4**: Python examples (flask, fastapi, django) — session config added
- [x] **Step 5**: Java/.NET/Rust examples (spring, aspnet, axum) — session config added
- [x] **Step 6**: Frontend HTML updated in all 15 server-only examples — auto-login after register
- [x] **Step 7**: Full-stack frontend UIs updated (Nuxt, SvelteKit, Remix, Astro, Next.js, React, Vue, Solid, Angular) — auto-login after register
- [x] **Step 8**: All 10 TS server package dists rebuilt

## Summary of Changes

### Server Packages (6 languages, auto-login after registration)
- `server-ts/src/passkey.ts` — `finishRegistration()` creates session token when session configured
- `server-ts/src/types.ts` — added `sessionToken?: string` to `FinishRegistrationResponse`
- `server-go/passkey.go` — `FinishRegistration()` sets session cookie when session configured
- `server-py/handlers.py` — `finish_registration()` returns sessionToken when session configured
- `server-spring/PasskeyService.java` — `finishRegistration()` returns sessionToken
- `server-aspnet/PasskeyService.cs` — `FinishRegistration()` returns sessionToken
- `server-axum/src/handlers.rs` — `finish_registration()` sets session cookie

### Framework Bindings (12 packages, cookie on register/finish)
All TS bindings (Express, Fastify, Hono, NestJS, Next.js, Nuxt, SvelteKit, Remix, Astro) + Python (Flask, FastAPI, Django) + Spring controller + ASP.NET endpoints now check for sessionToken on register/finish and set the Set-Cookie header.

### Example Configs (19 examples)
All examples now have session config with `secure: false` for localhost development.

### Frontend UIs (23 examples)
All examples auto-login after registration instead of showing "Registered! You can now sign in."
