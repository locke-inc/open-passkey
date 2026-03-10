Howdy! We are going to create an open-source repo in this greenfield folder called open-passkey. The goal is simple: an open library to effortlessly implement passkey authentication in any app.

While the eventual goal is ubiquitous adoption starting with TypeScript (Node) and React/Angular, our immediate system architecture is Go for the backend and Angular for the frontend, so we are going to build those out first.

An important requirement for this project is that the implementation must be quickly transferable to a myriad of programming languages and frameworks (Streamlit, Ruby on Rails, WordPress, Lovable, etc.). So we don't have to think about it later, let's agree on two baseline architectural decisions now:

Monorepo Structure: We will structure this as a monorepo to house both the core logic and the various framework wrappers.

Separation of Concerns: We will strictly separate the "Core Protocol" (the raw WebAuthn/cryptography logic) from the "Framework Bindings" (the Angular/Go/React specific wrappers).

I want to follow strict TDD (Test-Driven Development). Here is my question for you to help us think through the architecture:

How can we architect this repo such that it follows TDD for a multi-language future? Can we write tests in a language-agnostic way—perhaps by creating a shared suite of JSON test vectors (inputs/expected outputs for WebAuthn challenges/verifications) that every language's test suite imports and runs against? Or is that not feasible/an anti-pattern, and we should just have completely isolated test suites for every language?

Let's discuss the tradeoffs of both approaches. What do you recommend we set up first for our Go/Angular starting point?

-

Great question. Both approaches have merit, and the answer is: use both, but for different layers.

  The Two Testing Layers                                                                                 
   
  Layer 1: Shared JSON Test Vectors (Core Protocol)                                                      
                  
  This is not an anti-pattern — it's exactly how mature cryptographic and protocol libraries work. The
  WebAuthn spec itself effectively defines test vectors through its conformance testing. Here's why it
  works well for passkeys specifically:

  What's deterministic and shareable:
  - Parsing and validating clientDataJSON (it's just JSON with known fields)
  - Parsing authenticatorData (binary format with a rigid spec: rpIdHash, flags, counter,
  attestedCredentialData)
  - Verifying signatures given a known public key, challenge, and authenticator response
  - CBOR decoding of attestation objects
  - Challenge generation validation (length, encoding)

  A shared test vector file might look like:

  {
    "registration_verification": [
      {
        "name": "valid_registration_none_attestation",
        "input": {
          "rpId": "example.com",
          "expectedChallenge": "dGVzdC1jaGFsbGVuZ2U",
          "credential": {
            "id": "...",
            "rawId": "...",
            "response": {
              "clientDataJSON": "...",
              "attestationObject": "..."
            }
          }
        },
        "expected": {
          "success": true,
          "credentialId": "...",
          "publicKey": "...",
          "signCount": 0
        }
      },
      {
        "name": "wrong_rp_id_should_fail",
        "input": { "rpId": "evil.com", "..." : "..." },
        "expected": {
          "success": false,
          "error": "rp_id_mismatch"
        }
      }
    ]
  }

  Every language's core library reads the same vectors and asserts the same outcomes. When you add a new
  edge case, every implementation gets the test for free.

  The tradeoff: You need real, valid WebAuthn payloads captured or generated once. The initial investment
   is higher. But this is a one-time cost that pays dividends every time you add a new language.

  Layer 2: Isolated Test Suites (Framework Bindings)

  Shared vectors don't work for:
  - HTTP handler behavior (Go's net/http vs Express vs Rails)
  - Angular/React component rendering and user interaction
  - Session/cookie management
  - Framework-specific middleware integration
  - Database adapter behavior

  These are inherently framework-specific and should have completely isolated test suites written
  idiomatically for each language/framework.

  Recommended Architecture

  open-passkey/
  ├── spec/                          # Shared test vectors + schema
  │   ├── vectors/
  │   │   ├── registration.json      # Registration ceremony test cases
  │   │   ├── authentication.json    # Authentication ceremony test cases
  │   │   └── edge-cases.json        # Malformed inputs, boundary conditions
  │   ├── schema/                    # JSON Schema for vector validation
  │   └── README.md                  # How to generate/update vectors
  │
  ├── packages/
  │   ├── core-go/                   # Core protocol in Go
  │   │   ├── webauthn/              # Parsing, verification logic
  │   │   ├── webauthn_test.go       # Loads ../spec/vectors/*.json
  │   │   └── go.mod
  │   │
  │   ├── server-go/                 # Go HTTP bindings (Gin, net/http)
  │   │   ├── middleware/
  │   │   ├── middleware_test.go     # Isolated, idiomatic Go tests
  │   │   └── go.mod
  │   │
  │   ├── core-ts/                   # Core protocol in TypeScript
  │   │   ├── src/
  │   │   ├── src/__tests__/         # Loads ../../spec/vectors/*.json
  │   │   └── package.json
  │   │
  │   └── angular/                   # Angular component bindings
  │       ├── src/
  │       ├── src/__tests__/         # Isolated Angular tests
  │       └── package.json
  │
  └── CLAUDE.md

  The key insight: spec/ is the contract, packages/*/ are the implementations. Any new language starts by
   making spec/vectors/*.json tests pass.

  Why Not Vectors-Only or Isolated-Only?

  ┌─────────────────┬────────────────────────────────────────────────────────────────────────────────┐
  │    Approach     │                                    Problem                                     │
  ├─────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │ Vectors only    │ Can't test HTTP handlers, UI components, or framework integration. You'd       │
  │                 │ contort tests into an unnatural shape.                                         │
  ├─────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │                 │ Every new language re-derives edge cases from the spec. Bugs found in Go's     │
  │ Isolated only   │ tests never propagate to TypeScript. You'll inevitably have coverage gaps      │
  │                 │ between languages.                                                             │
  ├─────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │ Both            │ Core correctness is guaranteed uniformly. Framework tests stay idiomatic.      │
  │ (recommended)   │ Adding a new language has a clear "done" bar: all vectors pass.                │
  └─────────────────┴────────────────────────────────────────────────────────────────────────────────┘

  What to Set Up First

  For your Go + Angular starting point, I'd recommend this order:

  1. spec/vectors/ — Generate a small but real set of WebAuthn registration + authentication vectors. We
  can write a Go helper that uses a software authenticator to produce valid payloads, then capture them
  as JSON fixtures.
  2. packages/core-go/ — Implement core WebAuthn parsing/verification with tests that load from
  spec/vectors/. Strict TDD: write the vector loader first, watch tests fail, then implement.
  3. packages/server-go/ — HTTP handlers/middleware with isolated Go tests (httptest).
  4. packages/core-ts/ — TypeScript core that passes the same vectors (proving the architecture works
  cross-language).
  5. packages/angular/ — Angular components with isolated Karma/Jest tests.

  The critical first step is generating good test vectors. Want me to start scaffolding the repo
  structure and building the vector generation tooling?

✻ Worked for 32s                    

-

❯ Yes, this architecture is spot on. I love the distinction between the shared protocol vectors and the  
isolated framework tests.                                                                                
                                                                                                         
Let's execute Step 1 and Step 2.                                                                         
                                                                                                         
Please scaffold the directory structure you proposed. Then, write the Go helper tooling to generate our  
initial spec/vectors/ JSON files. We need at least the following baseline scenarios for both             
Registration and Authentication:                                                                         
                                                                                                         
Happy path (successful ceremony)                                                                         
                                                                                                         
Invalid/mismatched rpId                                                                                  
                                                                                                         
Expired or incorrect challenge                                                                           
                                                                                                         
Invalid signature                                                                                        
                                                                                                         
A few constraints for our Go implementation:                                                             
                                                                                                         
Keep third-party dependencies to an absolute minimum. Rely heavily on Go's standard crypto,              
encoding/json, and testing libraries.                                                                    
                                                                                                         
For the CBOR decoding (which WebAuthn requires), please select a lightweight, widely respected Go        
library and explain why you chose it.                                                                    
                                                                                                         
Go ahead and write the webauthn_test.go runner that loops through our new JSON vectors. It should fail   
initially (Strict TDD!).                                                                                 
                                                                                                         
Let me know when the scaffolding, vector generation, and failing tests are in place so we can review     
before implementing the actual core logic.        