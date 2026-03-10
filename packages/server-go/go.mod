module github.com/locke-inc/open-passkey/packages/server-go

go 1.23.3

require github.com/locke-inc/open-passkey/packages/core-go v0.0.0

require (
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)

replace github.com/locke-inc/open-passkey/packages/core-go => ../core-go
