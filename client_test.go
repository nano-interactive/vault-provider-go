package vault_provider_go

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault-client-go"
)

func TestIsKubernetes(t *testing.T) {
	// This will be false on your local machine
	res := isKubernetes()
	t.Logf("Is Kubernetes: %v", res)
}

func TestApplyDefaults_NilConfig(t *testing.T) {
	cfg := applyDefaults(nil)
	if cfg.VaultAddr != defaultVaultAddr() {
		t.Errorf("VaultAddr: got %q", cfg.VaultAddr)
	}
	if cfg.RoleName != "default" {
		t.Errorf("RoleName: got %q", cfg.RoleName)
	}
	if cfg.AuthPath != defaultAuthPath() {
		t.Errorf("AuthPath: got %q", cfg.AuthPath)
	}
}

func TestInjectSecrets_Mock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock KV v2 response: path like "myapp/config" returns data.data
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"api_key": "secret-value-123",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{VaultAddr: server.URL}
	cfg = applyDefaults(cfg)
	client, err := vault.New(vault.WithAddress(cfg.VaultAddr))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	vp := &VaultProvider{Client: client, Config: cfg}

	type AppConfig struct {
		APIKey string
		Plain  string
	}
	appCfg := &AppConfig{
		APIKey: "vault:myapp/config#api_key",
		Plain:  "leave-me-unchanged",
	}

	err = vp.InjectSecrets(context.Background(), appCfg)
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}
	if appCfg.APIKey != "secret-value-123" {
		t.Errorf("expected api_key to be replaced with secret, got %q", appCfg.APIKey)
	}
	if appCfg.Plain != "leave-me-unchanged" {
		t.Errorf("non-placeholder string should be unchanged, got %q", appCfg.Plain)
	}
}
