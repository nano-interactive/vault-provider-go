package vault_provider_go

import (
	"context"
	"reflect"
	"strings"
)

const vaultPrefix = "vault:"

// InjectSecrets walks appConfig (must be a pointer to a struct) and replaces any string
// value that exactly matches "vault:path#key" with the secret from Vault at path, key.
// If appConfig is nil or contains no placeholders, returns nil without contacting Vault.
// When placeholders exist, the provider initializes the Vault client and auth on first use.
func (vp *VaultProvider) InjectSecrets(ctx context.Context, appConfig interface{}) error {
	if appConfig == nil {
		return nil
	}

	v := reflect.ValueOf(appConfig)
	if v.Kind() != reflect.Pointer {
		return nil
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return nil
	}

	if !hasAnyPlaceholder(v) {
		return nil
	}
	if err := vp.ensureClient(ctx); err != nil {
		return err
	}
	return vp.injectSecretsRecurse(ctx, v)
}

// hasAnyPlaceholder reports whether the reflect value (or any nested string) contains
// a vault:path#key placeholder. Same shape as injectSecretsRecurse but read-only.
func hasAnyPlaceholder(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		_, _, ok := parsePlaceholder(v.String())
		return ok
	case reflect.Pointer:
		if v.IsNil() {
			return false
		}
		return hasAnyPlaceholder(v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if !f.CanSet() {
				continue
			}
			if hasAnyPlaceholder(f) {
				return true
			}
		}
		return false
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if hasAnyPlaceholder(v.Index(i)) {
				return true
			}
		}
		return false
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			val := iter.Value()
			if val.Kind() == reflect.String {
				if _, _, ok := parsePlaceholder(val.String()); ok {
					return true
				}
			} else if hasAnyPlaceholder(val) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (vp *VaultProvider) injectSecretsRecurse(ctx context.Context, v reflect.Value) error {
	switch v.Kind() {
	case reflect.String:
		s := v.String()
		if path, key, ok := parsePlaceholder(s); ok {
			secret, err := vp.readSecretAt(ctx, path, key)
			if err != nil {
				return err
			}
			v.SetString(secret)
		}
		return nil
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return vp.injectSecretsRecurse(ctx, v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if !f.CanSet() {
				continue // unexported
			}
			if err := vp.injectSecretsRecurse(ctx, f); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if err := vp.injectSecretsRecurse(ctx, v.Index(i)); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			val := iter.Value()
			if val.Kind() == reflect.String {
				s := val.String()
				if path, key, ok := parsePlaceholder(s); ok {
					secret, err := vp.readSecretAt(ctx, path, key)
					if err != nil {
						return err
					}
					v.SetMapIndex(iter.Key(), reflect.ValueOf(secret))
				}
			} else {
				if err := vp.injectSecretsRecurse(ctx, val); err != nil {
					return err
				}
			}
		}
		return nil
	default:
		return nil
	}
}

// parsePlaceholder returns (path, key, true) if s is exactly "vault:path#key".
func parsePlaceholder(s string) (path, key string, ok bool) {
	if !strings.HasPrefix(s, vaultPrefix) || !strings.Contains(s, "#") {
		return "", "", false
	}
	rest := s[len(vaultPrefix):]
	i := strings.Index(rest, "#")
	if i < 0 {
		return "", "", false
	}
	path = rest[:i]
	key = rest[i+1:]
	if path == "" || key == "" {
		return "", "", false
	}
	return path, key, true
}
