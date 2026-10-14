# AGENTS.md

Guidance for AI coding agents working in this repository.

## Overview

`github.com/smallstep/scep` is a Go library implementing the Simple Certificate Enrollment Protocol (SCEP) message layer: parsing and building `PKIMessage`s (PKCSReq, CertRep, etc.), decrypting the PKCS#7 `pkiEnvelope`, and producing `Success`/`Fail` CertRep responses. It is usable from both SCEP clients and servers; it contains no HTTP handling.

The package was extracted from the upstream [micromdm/scep](https://github.com/micromdm/scep) project and is maintained by Smallstep under the original MIT license (copyright Victor Vrantchan). `x509util/` additionally carries a BSD-3 header from the Go Authors. Preserve all existing license and copyright headers; do not relicense or strip attribution when editing or moving code.

The only third-party dependency is `github.com/smallstep/pkcs7` (also an upstream fork). `go.mod` declares `go 1.16` and a legacy CI job still builds on Go 1.16–1.18, so avoid newer language features and stdlib APIs.

## Commands

```bash
make test           # go test -cover ./...
make test-race      # go test -cover -race ./...
make lint           # golangci-lint (config fetched from smallstep/workflows) + govulncheck
make fmt            # goimports -l -w on all .go files
make bootstrap      # install golangci-lint, govulncheck, gotestsum
make all            # lint + test (default target)
```

Run a single test:

```bash
go test -run TestParsePKIMessage -v .
```

No build step, generated code, Docker, database, or environment variables are required. `go build ./...` and `go test ./...` work offline once modules are cached.

Test fixtures under `testdata/` are real certificates with fixed validity windows. `TestSignCSR` signs with `testdata/testca/ca.crt` + `ca.key` (the key is password-protected; see the test for the password), and `pkcs7` rejects a signing time outside the signer certificate's validity, so this test starts failing once that certificate expires. If it fails with `signing time ... is outside of certificate validity`, the fixture needs regenerating rather than the code.

## CI

- `.github/workflows/CI.yml` calls the shared `smallstep/workflows` `goCI.yml` with `run-lint: false` and `run-build: false`; it runs tests and CodeQL (`go build ./...`).
- `.github/workflows/ci-legacy.yml` builds and tests on Go 1.16.x, 1.17.x and 1.18.x and fails if `gofmt -s -l .` reports any file. Keep code `gofmt -s` clean.
- `.github/workflows/release.yml` creates a GitHub release on any `v*` tag; tags containing `-rc` are marked pre-release. There are no binaries; a release is a Go module version.
- `actionci.yml` runs actionlint and zizmor on workflow changes (`.github/zizmor.yml` holds its config).

## Layout

```
scep/
├── scep.go                # PKIMessage, ParsePKIMessage, DecryptPKIEnvelope, Success/Fail,
│                          # NewCSRRequest, CACerts, DegenerateCertificates, functional Options
├── certs_selector.go      # CertsSelector: pick recipient certs for the CertRep (nop, encipherment, fingerprint)
├── logger.go              # go-kit style Logger interface; nop logger by default
├── cryptoutil/            # GenerateSubjectKeyID
├── x509util/              # CSR creation with challengePassword attribute; ParseChallengePassword
│                          # (adapted from Go stdlib crypto/x509, BSD-3 header)
└── testdata/              # DER-encoded PKCSReq/CertRep messages and test CA/client certs
```

Message flow on the server side: `ParsePKIMessage(body)` -> `msg.DecryptPKIEnvelope(caCert, caKey)` -> read `msg.CSRReqMessage.CSR` (and `ChallengePassword`) -> sign the CSR with your own CA -> `msg.Success(caCert, caKey, cert)` or `msg.Fail(caCert, caKey, info)` -> write `certRep.Raw`.

Client side: `x509util.CreateCertificateRequest` builds a CSR carrying the challenge password, then `NewCSRRequest(csr, tmpl, opts...)` wraps it in a signed and encrypted PKCSReq.

## Conventions

- Errors: standard library only, `fmt.Errorf("scep: ...: %w", err)` and `errors.New`. Do not add `github.com/pkg/errors`.
- Options: `ParsePKIMessage` and `NewCSRRequest` take functional `Option`s (`WithLogger`, `WithCACerts`, `WithCertsSelector`). Add new configuration the same way rather than changing signatures.
- Logging: only through the `Logger` interface (`Log(keyvals ...interface{}) error`); never import a concrete logging library.
- Tests: standard `testing` package, table-driven with `t.Run`, no testify. Fixtures are loaded from `testdata/` via `os.ReadFile`. Add new fixtures there rather than embedding large byte slices.
- Keep the public API minimal and backward compatible; downstream users import this module by version.
