package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	passkey "github.com/locke-inc/open-passkey/packages/server-go"
)

func main() {
	p, err := passkey.New(passkey.Config{
		RPID:            "localhost",
		RPDisplayName:   "Open Passkey Echo Example",
		Origin:          "http://localhost:4003",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
		Session: &passkey.SessionConfig{
			Secret: "echo-example-secret-must-be-32-charss!",
			Secure: func() *bool { b := false; return &b }(),
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create passkey: %v\n", err)
		os.Exit(1)
	}

	e := echo.New()

	// Adapter: wrap net/http handler for Echo
	wrap := func(h http.HandlerFunc) echo.HandlerFunc {
		return echo.WrapHandler(h)
	}

	// Passkey API routes
	e.POST("/passkey/register/begin", wrap(p.BeginRegistration))
	e.POST("/passkey/register/finish", wrap(p.FinishRegistration))
	e.POST("/passkey/login/begin", wrap(p.BeginAuthentication))
	e.POST("/passkey/login/finish", wrap(p.FinishAuthentication))
	e.GET("/passkey/session", wrap(p.GetSession))
	e.POST("/passkey/logout", wrap(p.Logout))

	// Shared static files (passkey.js, style.css)
	e.File("/passkey.js", "../shared/passkey.js")
	e.File("/style.css", "../shared/style.css")

	// Local static files (index.html)
	e.Static("/", "public")

	fmt.Println("Echo (server-go) example running on http://localhost:4003")
	e.Logger.Fatal(e.Start(":4003"))
}
