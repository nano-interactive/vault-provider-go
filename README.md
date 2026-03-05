# vault-provider-go

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

<p align="center">
  <img src="assets/icon.png" width="128" alt="vault-provider-go icon" />
</p>

A small Go library that fetches [HashiCorp Vault](https://www.vaultproject.io/) credentials at startup and injects them into your application config by reference. It supports running **in Kubernetes** (JWT login) and **locally** (OIDC SSO in the browser), with environment detected automatically.

## Features

- **Config injection**: Pass a pointer to your config struct; any string field set to `vault:path#key` is replaced with the secret from Vault (in place).
- **Optional config**: All provider settings have defaults; you can pass `nil` or only override what you need.
- **Dual run mode**: In-cluster uses Kubernetes auth; on a developer machine uses OIDC (browser). No extra configuration required.

## Installation

```bash
go get github.com/nano-interactive/vault-provider-go
```

Requires Go 1.25+ and `github.com/hashicorp/vault-client-go` v0.4.3.

## Quick start

```go
package main

import (
    "context"
    "log"

    vault_provider_go "github.com/nano-interactive/vault-provider-go"
)

type AppConfig struct {
    APIKey    string
    DBConnStr string
}

func main() {
    // Nil config uses all defaults (see Defaults below).
    vp, err := vault_provider_go.New(nil)
    if err != nil {
        log.Fatal(err)
    }

    cfg := &AppConfig{
        APIKey:    "vault:app/data/myapp/credentials#api_key",
        DBConnStr: "vault:app/data/myapp/credentials#database_url",
    }

    if err := vp.InjectSecrets(context.Background(), cfg); err != nil {
        log.Fatal(err)
    }

    // cfg.APIKey and cfg.DBConnStr now hold the real secret values.
}
```

## Placeholder format

Any **string** field (including inside nested structs, slices, or maps) whose value is exactly:

```text
vault:<path>#<key>
```

is replaced with the secret at that Vault path and key. The library walks your config by reflection and only mutates strings that match this pattern.

- **path**: Vault KV path (e.g. `app/data/myapp/credentials`).
- **key**: Key name at that path (e.g. `api_key`).

Both KV v1 and KV v2 engines are supported (v2 nesting under `data` is handled automatically).

## Optional configuration

You can pass a partial or full config. Empty fields are filled from defaults.

```go
// Use defaults for everything.
vp, err := vault_provider_go.New(nil)

// Override only Vault address and role.
vp, err := vault_provider_go.New(&vault_provider_go.Config{
    VaultAddr: "https://vault.example.com",
    RoleName:  "my-role",
})

// Load from your own config file (e.g. YAML).
var providerCfg vault_provider_go.Config
// ... decode into providerCfg ...
vp, err := vault_provider_go.New(&providerCfg)
```

See [config.example.yml](config.example.yml) for a sample YAML layout.

### Config fields

| Field       | YAML key     | Description                                      |
|------------|--------------|--------------------------------------------------|
| `VaultAddr`| `vault_addr` | Vault server URL.                                |
| `RoleName` | `role_name`  | Auth role name (e.g. Kubernetes role or OIDC).  |
| `AuthPath` | `auth_path`  | Auth method mount path (see Run modes).          |

## Defaults

When a field is not set (or config is `nil`), the library uses:

| Field       | Default |
|------------|---------|
| `VaultAddr`| `http://127.0.0.1:8200` |
| `RoleName` | `default` |
| `AuthPath` | **Local**: `oidc` — **Kubernetes**: `kubernetes` (chosen automatically) |

No environment variables are used; only the config (or these defaults) drive behaviour.

## Run modes

- **Kubernetes**: If the process runs inside a pod (detected via `/var/run/secrets/kubernetes.io/serviceaccount/token`), the library uses **Kubernetes auth** (JWT from the service account). No browser; no local token file.
- **Local**: Otherwise it uses **OIDC auth**: it opens a browser for SSO, then stores the token in `~/.vault-token` and reuses it on the next run.

Same code and config work in both environments; override `AuthPath` only if your Vault uses a non-default mount (e.g. `oidc-dev` or `kubernetes-staging`).

## Project layout

```text
.
├── config.go          # Config struct, defaults, applyDefaults
├── client.go          # New(), VaultProvider, readSecretAt, isKubernetes
├── inject.go          # InjectSecrets, placeholder parsing, reflection walk
├── auth_local.go      # OIDC flow (browser, ~/.vault-token)
├── auth_k8s.go        # Kubernetes JWT login
├── client_test.go     # Unit tests (mock Vault, defaults, inject)
├── integration_test.go # Integration test (real Vault; skip with -short)
├── config.example.yml # Example provider config and placeholder usage
├── go.mod
├── LICENSE
└── README.md
```

## Contributing

1. **Code style**: Follow normal Go conventions (e.g. `gofmt`). Keep the public API small: `Config`, `New`, `InjectSecrets`.
2. **Tests**: Run unit tests with `go test -short ./...`. Add or update tests in `client_test.go` for new behaviour; use mocks (e.g. `httptest`) so CI does not need Vault.
3. **Integration tests**: The integration test in `integration_test.go` talks to a real Vault (OIDC or token). It is skipped when `-short` is set. Run it manually when changing auth or injection: `go test -v -run TestIntegration_InjectSecrets ./...`.
4. **Defaults**: Changing defaults (e.g. `defaultVaultAddr`, `defaultAuthPath`) affects all users; document any change in the README and consider backwards compatibility.
5. **Auth flow**: Do not alter the existing auth branching in `client.go` (`isKubernetes()` → `authKubernetes` / `authLocal`) without updating this README and the run modes section.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for the full text.
