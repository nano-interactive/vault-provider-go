package vault_provider_go

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func (vp *VaultProvider) authLocal(ctx context.Context) error {
	tokenFile := filepath.Join(os.Getenv("HOME"), ".vault-token")
	cleanPath := strings.Trim(vp.Config.AuthPath, "/")
	baseAddr := strings.TrimSuffix(vp.Config.VaultAddr, "/")

	// 1. Existing Token Check
	if data, err := os.ReadFile(tokenFile); err == nil {
		vp.Client.SetToken(strings.TrimSpace(string(data)))
		if _, err := vp.Client.Auth.TokenLookUpSelf(ctx); err == nil {
			return nil
		}
	}

	tokenChan := make(chan string)
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		_ = r.ParseForm()
		code := r.FormValue("code")
		state := r.FormValue("state")

		// Exchange code for token: Vault's callback endpoint accepts GET with code/state in query (browser redirect style).
		exchangeURL := fmt.Sprintf("%s/v1/auth/%s/oidc/callback?code=%s&state=%s",
			baseAddr, cleanPath, url.QueryEscape(code), url.QueryEscape(state))

		req, _ := http.NewRequestWithContext(ctx, "GET", exchangeURL, nil)

		// If your staging Vault uses Namespaces (e.g., 'staging'), uncomment this:
		// req.Header.Set("X-Vault-Namespace", "staging")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Fprintf(w, "Network Error: %v", err)
			tokenChan <- ""
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			// This will show up in the BROWSER
			fmt.Fprintf(w, "Vault Error %d: %s", resp.StatusCode, string(body))
			// This will show up in your TERMINAL
			fmt.Printf("\n--- VAULT ERROR DEBUG ---\nURL: %s\nStatus: %d\nBody: %s\n------------------------\n", exchangeURL, resp.StatusCode, string(body))
			tokenChan <- ""
			return
		}

		var result struct {
			Auth struct {
				ClientToken string `json:"client_token"`
			} `json:"auth"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&result)
		if result.Auth.ClientToken == "" {
			fmt.Fprint(w, "Vault response missing client_token. Check Vault auth config and redirect_uri (http://localhost:8250/oidc/callback).")
			fmt.Print("\n--- VAULT OIDC DEBUG: 200 OK but no client_token in response ---\n")
			tokenChan <- ""
			return
		}
		fmt.Fprint(w, "Login Successful! Check terminal.")
		tokenChan <- result.Auth.ClientToken
	})

	srv := &http.Server{Addr: "127.0.0.1:8250", Handler: mux}
	go srv.ListenAndServe()
	defer srv.Shutdown(ctx)

	// 3. Get Auth URL (Standard)
	rawClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	body, _ := json.Marshal(map[string]interface{}{
		"role": vp.Config.RoleName, "redirect_uri": "http://localhost:8250/oidc/callback",
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/v1/auth/%s/oidc/auth_url", baseAddr, cleanPath), bytes.NewBuffer(body))
	// req.Header.Set("X-Vault-Namespace", "staging") // Set namespace here too if used

	res, err := rawClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var authURL string
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		authURL = res.Header.Get("Location")
	} else {
		var r struct {
			Data struct {
				AuthURL string `json:"auth_url"`
			} `json:"data"`
		}
		_ = json.NewDecoder(res.Body).Decode(&r)
		authURL = r.Data.AuthURL
	}
	if authURL == "" {
		return fmt.Errorf("invalid auth url")
	}

	_ = openBrowser(authURL)
	select {
	case token := <-tokenChan:
		if token == "" {
			return fmt.Errorf("OIDC flow failed: no token received (complete login in browser, ensure redirect_uri is http://localhost:8250/oidc/callback, or check terminal for Vault error)")
		}
		vp.Client.SetToken(token)
		_ = os.WriteFile(tokenFile, []byte(token), 0600)
		return nil
	case <-time.After(5 * time.Minute):
		return fmt.Errorf("timeout")
	}
}

// openBrowser opens the specified URL in the user's default browser.
func openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin": // macOS
		cmd = "open"
		args = []string{url}
	default: // Linux and others
		cmd = "xdg-open"
		args = []string{url}
	}

	// Use Start() instead of Run() so we don't block the execution
	// of the rest of the library while the browser is open.
	return exec.Command(cmd, args...).Start()
}
