package main

import (
	"fmt"
	"net/http"
	"os"

	passkey "github.com/locke-inc/open-passkey/packages/server-nethttp"
)

func main() {
	p, err := passkey.New(passkey.Config{
		RPID:            "localhost",
		RPDisplayName:   "Open Passkey Net/HTTP Example",
		Origin:          "http://localhost:4002",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create passkey: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	// Passkey API routes (Handler returns a mux with all routes registered)
	mux.Handle("/passkey/", http.StripPrefix("/passkey", p.Handler()))

	// Shared static files (passkey.js, style.css)
	mux.Handle("/passkey.js", http.FileServer(http.Dir("../shared")))
	mux.Handle("/style.css", http.FileServer(http.Dir("../shared")))

	// Local static files (index.html)
	mux.Handle("/", http.FileServer(http.Dir("public")))

	fmt.Println("Net/HTTP (server-nethttp) example running on http://localhost:4002")
	if err := http.ListenAndServe(":4002", mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
