module github.com/locke-inc/open-passkey/examples/fiber

go 1.23.3

require (
	github.com/gofiber/fiber/v2 v2.52.6
	github.com/locke-inc/open-passkey/packages/server-go v0.0.0
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/locke-inc/open-passkey/packages/core-go v0.0.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.51.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace (
	github.com/locke-inc/open-passkey/packages/core-go => ../../packages/core-go
	github.com/locke-inc/open-passkey/packages/server-go => ../../packages/server-go
)
