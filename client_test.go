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

func TestNew_NoVaultContact(t *testing.T) {
	vp, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil) should not fail: %v", err)
	}
	if vp == nil {
		t.Fatal("New(nil) should return non-nil provider")
	}
	if vp.Client != nil {
		t.Error("New(nil) should not set Client; init is lazy")
	}
	if vp.Config == nil {
		t.Error("New(nil) should set Config from defaults")
	}
}

func TestInjectSecrets_NoPlaceholders_NoVaultCall(t *testing.T) {
	vp, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	type AppConfig struct {
		Plain string
	}
	appCfg := &AppConfig{Plain: "leave-me-unchanged"}

	err = vp.InjectSecrets(context.Background(), appCfg)
	if err != nil {
		t.Fatalf("InjectSecrets with no placeholders should not fail: %v", err)
	}
	if appCfg.Plain != "leave-me-unchanged" {
		t.Errorf("config should be unchanged, got %q", appCfg.Plain)
	}
	if vp.Client != nil {
		t.Error("InjectSecrets with no placeholders should not create Client")
	}
}

func TestInjectSecrets_Mock_MapRoot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"api_key": "secret-from-map-root",
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

	m := map[string]interface{}{
		"api_key": "vault:myapp/config#api_key",
		"plain":   "unchanged",
	}

	err = vp.InjectSecrets(context.Background(), &m)
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}
	if m["api_key"] != "secret-from-map-root" {
		t.Errorf("expected api_key to be replaced, got %q", m["api_key"])
	}
	if m["plain"] != "unchanged" {
		t.Errorf("plain should be unchanged, got %q", m["plain"])
	}
}

func TestInjectSecrets_Mock_PointerToInterfaceMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"token": "injected-token",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	providerCfg := &Config{VaultAddr: server.URL}
	providerCfg = applyDefaults(providerCfg)
	client, err := vault.New(vault.WithAddress(providerCfg.VaultAddr))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	vp := &VaultProvider{Client: client, Config: providerCfg}

	var appCfg interface{} = map[string]interface{}{
		"secret": "vault:some/path#token",
	}

	err = vp.InjectSecrets(context.Background(), &appCfg)
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}
	got, _ := appCfg.(map[string]interface{})
	if got == nil {
		t.Fatal("config should still be a map")
	}
	if got["secret"] != "injected-token" {
		t.Errorf("expected secret to be replaced, got %q", got["secret"])
	}
}
