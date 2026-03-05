package vault_provider_go

import (
	"context"
	"testing"
)

func TestIntegration_InjectSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	cfg := &Config{
		VaultAddr: "https://vault-api-staging.nanointeractive.com",
		RoleName:  "default",
		AuthPath:  "oidc",
	}

	vp, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to initialize VaultProvider: %v", err)
	}

	type AppConfig struct {
		SecretField string
	}
	appCfg := &AppConfig{
		SecretField: "vault:app/data/zap-scan/credentials#aws_default_region",
	}

	err = vp.InjectSecrets(context.Background(), appCfg)
	if err != nil {
		t.Fatalf("InjectSecrets failed: %v", err)
	}

	if appCfg.SecretField == "vault:app/data/zap-scan/credentials#aws_default_region" {
		t.Error("SecretField was not replaced: still the placeholder")
	}
	if appCfg.SecretField == "" {
		t.Error("SecretField is empty after inject")
	}
}
