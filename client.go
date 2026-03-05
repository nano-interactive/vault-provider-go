package vault_provider_go

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/vault-client-go"
)

type VaultProvider struct {
	Client *vault.Client
	Config *Config
}

func New(cfg *Config) (*VaultProvider, error) {
	cfg = applyDefaults(cfg)

	ctx := context.TODO()
	vCfg := vault.DefaultConfiguration()
	vCfg.Address = cfg.VaultAddr

	// Create a custom HTTP client that refuses to follow redirects.
	// This prevents the "at most one redirect is allowed" error during OIDC.
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// This is the magic: tell Go NOT to follow any redirects.
			// It will return the 302 response to the SDK instead of following it.
			return http.ErrUseLastResponse
		},
	}

	client, err := vault.New(
		vault.WithAddress(cfg.VaultAddr),
		vault.WithHTTPClient(httpClient),
		vault.WithRequestTimeout(10*time.Second),
	)
	if err != nil {
		return nil, err
	}

	vp := &VaultProvider{Client: client, Config: cfg}

	// Determine Environment
	if isKubernetes() {
		err = vp.authKubernetes(ctx)
	} else {
		err = vp.authLocal(ctx)
	}

	if err != nil {
		return nil, fmt.Errorf("auth failed: %w", err)
	}

	return vp, nil
}

func isKubernetes() bool {
	_, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return err == nil
}

// readSecretAt reads a secret at the given path and returns the value for the given key.
// Supports KV v2 (data nested under "data") and KV v1 (data at root).
func (vp *VaultProvider) readSecretAt(ctx context.Context, path, key string) (string, error) {
	if vp.Client == nil {
		return "", fmt.Errorf("vault provider client is nil")
	}

	resp, err := vp.Client.Read(ctx, path)
	if err != nil {
		return "", fmt.Errorf("read path %s: %w", path, err)
	}
	if resp == nil || resp.Data == nil {
		return "", fmt.Errorf("secret not found at %s", path)
	}

	var data map[string]interface{}
	if nested, ok := resp.Data["data"].(map[string]interface{}); ok {
		data = nested // KV v2
	} else {
		data = resp.Data // KV v1
	}

	v, ok := data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found at %s", key, path)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("key %q at %s is not a string", key, path)
	}
	return s, nil
}
