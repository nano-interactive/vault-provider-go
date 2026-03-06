package vault_provider_go

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/vault-client-go"
)

type VaultProvider struct {
	Client *vault.Client
	Config *Config

	initOnce sync.Once
	initErr  error
}

// New returns a VaultProvider with config applied. It does not contact Vault.
// The client is created and auth runs lazily on the first InjectSecrets call
// that finds at least one vault:path#key placeholder in the config.
func New(cfg *Config) (*VaultProvider, error) {
	cfg = applyDefaults(cfg)
	return &VaultProvider{Config: cfg}, nil
}

// ensureClient creates the Vault client and runs auth if not already done.
// If Client is already set (e.g. by tests), it returns nil without changing it.
// Safe for concurrent use; only one init runs.
func (vp *VaultProvider) ensureClient(ctx context.Context) error {
	if vp.Client != nil {
		return nil
	}
	vp.initOnce.Do(func() {
		vp.initErr = vp.doInit(ctx)
	})
	return vp.initErr
}

func (vp *VaultProvider) doInit(ctx context.Context) error {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	client, err := vault.New(
		vault.WithAddress(vp.Config.VaultAddr),
		vault.WithHTTPClient(httpClient),
		vault.WithRequestTimeout(10*time.Second),
	)
	if err != nil {
		return err
	}
	vp.Client = client
	if isKubernetes() {
		err = vp.authKubernetes(ctx)
	} else {
		err = vp.authLocal(ctx)
	}
	if err != nil {
		return fmt.Errorf("auth failed: %w", err)
	}
	return nil
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
