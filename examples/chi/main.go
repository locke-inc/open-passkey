package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	passkey "github.com/locke-inc/open-passkey/packages/server-chi"
)

func main() {
	p, err := passkey.New(passkey.Config{
		RPID:            "localhost",
		RPDisplayName:   "Open Passkey Chi Example",
		Origin:          "http://localhost:4005",
		ChallengeStore:  passkey.NewMemoryChallengeStore(),
		CredentialStore: passkey.NewMemoryCredentialStore(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create passkey: %v\n", err)
		os.Exit(1)
	}

	r := chi.NewRouter()

	// Passkey API routes
	r.Mount("/passkey", p.Routes())

	// Shared static files (passkey.js, style.css)
	sharedFS := http.FileServer(http.Dir("../shared"))
	r.Handle("/passkey.js", sharedFS)
	r.Handle("/style.css", sharedFS)

	// Local static files (index.html)
	r.Handle("/*", http.FileServer(http.Dir("public")))

	fmt.Println("Chi (server-chi) example running on http://localhost:4005")
	if err := http.ListenAndServe(":4005", r); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
