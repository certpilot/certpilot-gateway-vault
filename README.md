# certpilot-gateway-vault

A [CertPilot](https://github.com/certpilot/certpilot) gateway for HashiCorp
Vault's PKI secrets engine.

Implements [`provider.v1`](https://github.com/certpilot/certpilot-gateway-sdk).

```
docker run --rm -p 9093:9093 ghcr.io/certpilot/gateway-vault:0.2.0
```

## What it does

| | |
|:---|:---|
| Auth | AppRole, or a token |
| Key types | RSA, ECDSA, Ed25519 |
| CSRs | honoured — `sign` rather than `issue` when one is supplied |
| Revocation | yes |
| CA info | yes — the issuing chain behind the mount, so it lands in the inventory |

**`role` is required and the refusal says why:** a PKI role is what constrains
which names and key types a mount will sign. Issuing without a role means
issuing without constraints, which is not a default worth having.

## Credentials

**This gateway holds no credential of its own.** Each CA account carries the
Vault address, the mount, the role and the AppRole or token it issues under.
They arrive in `provider_config` on every call, so the process is authorised to
sign nothing.

## Facts about Vault that cost time to learn

Each of these is handled here, and each was found the hard way:

- **`sys/health` is not wrapped in the `data` envelope.** Decoding it through
  the envelope yields a zero value, which reads as "not initialized" for a Vault
  that is up and answering.
- **Vault refuses to sign past its issuer's expiry** rather than truncating the
  certificate. Every renewal through that mount fails at once, and the error
  does not say that is what happened.
- **Serials are colon-separated hex** from `big.Int.Bytes()`. Go's `Text(16)`
  drops leading zeros, so pad to even length before regrouping or the serial
  will not match.
- **On a `no_store` role, revoking by serial returns 400 and revoking by
  certificate succeeds.** They are different operations with different
  requirements, not two spellings of one.

## A lab Vault

```
./scripts/lab-vault.sh          # root, healthy intermediate, one deliberately expiring, a no_store role, an AppRole
./scripts/lab-vault.sh --env    # the variables the live tests look for
```

`live_test.go` skips unless `CERTPILOT_TEST_VAULT_ADDR`, `_ROLE_ID` and
`_SECRET_ID` are set, so `go test ./...` is safe with no Vault anywhere.

Vault installs from `brew tap hashicorp/tap`; it is no longer in homebrew-core.

## Flags

```
-port              9093
-address           default Vault address for accounts that do not name one, and what HealthCheck probes
-insecure          serve without TLS. Loopback only
-tls-cert/-tls-key/-tls-ca
```

## Conformance

```
go run github.com/certpilot/certpilot-gateway-sdk/cmd/conformance@latest \
    -addr localhost:9093 -insecure -config "$(cat account.json)"
```

Without `-config` the CA-dependent checks are skipped, because this gateway
cannot reach a Vault without credentials and says so.

## Releases

`0.2.0`, on `linux/amd64` and `linux/arm64`. Images publish on a tag, never on a
merge, so `latest` means the most recent release rather than the most recent
commit — pin anyway for anything you depend on.

The Go module is tagged in step with the image, so
`go run github.com/certpilot/certpilot-gateway-vault/cmd@v0.2.0` runs the same code
the image contains.

## Licence

Apache 2.0.
