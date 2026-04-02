package main

import (
	"fmt"
	"os"

	"github.com/labstack/echo/v4"
	passkey "github.com/locke-inc/open-passkey/packages/server-echo"
)

func main() {
	p, err := passkey.New(passkey.Config{
		RPID:            "localhost",
		RPDisplayName:   "Open Passkey Echo Example",
		Origin:          "http://localhost:4003",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create passkey: %v\n", err)
		os.Exit(1)
	}

	e := echo.New()

	// Passkey API routes
	p.RegisterRoutes(e, "/passkey")

	// Shared static files (passkey.js, style.css)
	e.Static("/", "../shared")

	// Local static files (index.html)
	e.Static("/", "public")

	fmt.Println("Echo (server-echo) example running on http://localhost:4003")
	e.Logger.Fatal(e.Start(":4003"))
}
