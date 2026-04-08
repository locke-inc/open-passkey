package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	passkey "github.com/locke-inc/open-passkey/packages/server-go"
)

func main() {
	p, err := passkey.New(passkey.Config{
		RPID:            "localhost",
		RPDisplayName:   "Open Passkey Chi Example",
		Origin:          "http://localhost:4005",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
		Session: &passkey.SessionConfig{
			Secret: "chi-example-secret-must-be-32-charss!!",
			Secure: func() *bool { b := false; return &b }(),
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create passkey: %v\n", err)
		os.Exit(1)
	}

	r := chi.NewRouter()

	// Passkey API routes — Chi accepts http.HandlerFunc directly
	r.Post("/passkey/register/begin", p.BeginRegistration)
	r.Post("/passkey/register/finish", p.FinishRegistration)
	r.Post("/passkey/login/begin", p.BeginAuthentication)
	r.Post("/passkey/login/finish", p.FinishAuthentication)
	r.Get("/passkey/session", p.GetSession)
	r.Post("/passkey/logout", p.Logout)

	// Shared static files (passkey.js, style.css)
	sharedFS := http.FileServer(http.Dir("../shared"))
	r.Handle("/passkey.js", sharedFS)
	r.Handle("/style.css", sharedFS)

	// Local static files (index.html)
	r.Handle("/*", http.FileServer(http.Dir("public")))

	fmt.Println("Chi (server-go) example running on http://localhost:4005")
	if err := http.ListenAndServe(":4005", r); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
