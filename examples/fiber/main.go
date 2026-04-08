package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	passkey "github.com/locke-inc/open-passkey/packages/server-go"
)

func main() {
	p, err := passkey.New(passkey.Config{
		RPID:            "localhost",
		RPDisplayName:   "Open Passkey Fiber Example",
		Origin:          "http://localhost:4004",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
		Session: &passkey.SessionConfig{
			Secret: "fiber-example-secret-must-be-32-chars!",
			Secure: func() *bool { b := false; return &b }(),
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create passkey: %v\n", err)
		os.Exit(1)
	}

	app := fiber.New()

	// Adapter: wrap net/http handler for Fiber
	wrap := func(h http.HandlerFunc) fiber.Handler {
		return adaptor.HTTPHandlerFunc(h)
	}

	// Passkey API routes
	app.Post("/passkey/register/begin", wrap(p.BeginRegistration))
	app.Post("/passkey/register/finish", wrap(p.FinishRegistration))
	app.Post("/passkey/login/begin", wrap(p.BeginAuthentication))
	app.Post("/passkey/login/finish", wrap(p.FinishAuthentication))
	app.Get("/passkey/session", wrap(p.GetSession))
	app.Post("/passkey/logout", wrap(p.Logout))

	// Shared static files (passkey.js, style.css)
	app.Static("/", "../shared")

	// Local static files (index.html)
	app.Static("/", "./public")

	fmt.Println("Fiber (server-go) example running on http://localhost:4004")
	if err := app.Listen(":4004"); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
