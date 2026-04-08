package main

import (
	"fmt"
	"net/http"
	"os"

	passkey "github.com/locke-inc/open-passkey/packages/server-go"
)

func main() {
	p, err := passkey.New(passkey.Config{
		RPID:            "localhost",
		RPDisplayName:   "Open Passkey Gin Example",
		Origin:          "http://localhost:4001",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
		Session: &passkey.SessionConfig{
			Secret: "gin-example-secret-must-be-32-charss!",
			Secure: func() *bool { b := false; return &b }(),
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create passkey: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	// Passkey API routes
	mux.HandleFunc("POST /passkey/register/begin", p.BeginRegistration)
	mux.HandleFunc("POST /passkey/register/finish", p.FinishRegistration)
	mux.HandleFunc("POST /passkey/login/begin", p.BeginAuthentication)
	mux.HandleFunc("POST /passkey/login/finish", p.FinishAuthentication)
	mux.HandleFunc("GET /passkey/session", p.GetSession)
	mux.HandleFunc("POST /passkey/logout", p.Logout)

	// Shared static files (passkey.js, style.css)
	mux.Handle("/passkey.js", http.FileServer(http.Dir("../shared")))
	mux.Handle("/style.css", http.FileServer(http.Dir("../shared")))

	// Local static files (index.html)
	mux.Handle("/", http.FileServer(http.Dir("public")))

	fmt.Println("Gin (server-go) example running on http://localhost:4001")
	if err := http.ListenAndServe(":4001", mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
