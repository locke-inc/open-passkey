package main

import (
	"fmt"
	"os"

	"github.com/gofiber/fiber/v2"
	passkey "github.com/locke-inc/open-passkey/packages/server-fiber"
)

func main() {
	p, err := passkey.New(passkey.Config{
		RPID:            "localhost",
		RPDisplayName:   "Open Passkey Fiber Example",
		Origin:          "http://localhost:4004",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create passkey: %v\n", err)
		os.Exit(1)
	}

	app := fiber.New()

	// Passkey API routes
	p.RegisterRoutes(app, "/passkey")

	// Shared static files (passkey.js, style.css)
	app.Static("/", "../shared")

	// Local static files (index.html)
	app.Static("/", "./public")

	fmt.Println("Fiber (server-fiber) example running on http://localhost:4004")
	if err := app.Listen(":4004"); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
