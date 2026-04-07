module github.com/locke-inc/open-passkey/examples/echo

go 1.25

require (
	github.com/labstack/echo/v4 v4.13.3
	github.com/locke-inc/open-passkey/packages/server-go v0.0.0
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/locke-inc/open-passkey/packages/core-go v0.0.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)

replace (
	github.com/locke-inc/open-passkey/packages/core-go => ../../packages/core-go
	github.com/locke-inc/open-passkey/packages/server-go => ../../packages/server-go
)
