package vault_provider_go

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

func (vp *VaultProvider) authKubernetes(ctx context.Context) error {
	// Read the K8s JWT from the standard mount path
	jwt, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return fmt.Errorf("could not read k8s jwt: %w", err)
	}

	// Perform login (AuthPath defaults to "kubernetes" when in-cluster)
	resp, err := vp.Client.Auth.KubernetesLogin(ctx, schema.KubernetesLoginRequest{
		Jwt:  string(jwt),
		Role: vp.Config.RoleName,
	}, vault.WithMountPath(vp.Config.AuthPath))
	if err != nil {
		return fmt.Errorf("vault k8s login failed: %w", err)
	}

	// Set the token for the client
	return vp.Client.SetToken(resp.Auth.ClientToken)
}
