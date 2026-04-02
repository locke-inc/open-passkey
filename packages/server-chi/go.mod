module github.com/locke-inc/open-passkey/packages/server-chi

go 1.23.3

require (
	github.com/go-chi/chi/v5 v5.2.1
	github.com/locke-inc/open-passkey/packages/core-go v0.0.1
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/locke-inc/open-passkey/packages/core-go => ../core-go
