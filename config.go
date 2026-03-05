package vault_provider_go

type Config struct {
	VaultAddr string `yaml:"vault_addr"`
	RoleName  string `yaml:"role_name"`
	AuthPath  string `yaml:"auth_path"` // e.g., "oidc" or "kubernetes"
}

// defaultVaultAddr returns the default Vault address when not set in config.
// Standard local Vault dev server; override in config for your environment.
func defaultVaultAddr() string {
	return "http://127.0.0.1:8200"
}

// defaultAuthPath returns "kubernetes" when running in K8s, "oidc" otherwise.
func defaultAuthPath() string {
	if isKubernetes() {
		return "kubernetes"
	}
	return "oidc"
}

// applyDefaults returns a config with empty fields filled from defaults. cfg may be nil.
func applyDefaults(cfg *Config) *Config {
	out := &Config{
		VaultAddr: defaultVaultAddr(),
		RoleName:  "default",
		AuthPath:  defaultAuthPath(),
	}
	if cfg == nil {
		return out
	}
	if cfg.VaultAddr != "" {
		out.VaultAddr = cfg.VaultAddr
	}
	if cfg.RoleName != "" {
		out.RoleName = cfg.RoleName
	}
	if cfg.AuthPath != "" {
		out.AuthPath = cfg.AuthPath
	}
	return out
}
