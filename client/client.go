// Package client provides the core HTTP client, authentication, and configuration for Teltonika RMS API.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/carrier-labs/go-teltonika-rms-api-client/debug"
)

const (
	DefaultBaseURL = "https://rms.teltonika-networks.com/api"
	AuthEndpoint   = "https://rms.teltonika-networks.com/account/authorize"
	TokenEndpoint  = "https://rms.teltonika-networks.com/account/token"
)

// Config holds configuration for the RMS API client (OAuth2 Authorization Code Flow).
type Config struct {
	BaseURL      string        // Optional; if empty, DefaultBaseURL is used
	ClientID     string        // OAuth2 Client ID
	ClientSecret string        // OAuth2 Client Secret (for confidential clients)
	RedirectURI  string        // OAuth2 Redirect URI
	Scopes       []string      // OAuth2 scopes
	Timeout      time.Duration // Optional; if zero, 10s is used
	PAT          string        // Personal Access Token (optional)
}

// Client is the main struct for interacting with the RMS API.
type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	httpClient   *http.Client
	mu           sync.Mutex
	accessToken  string
	refreshToken string
	expiresAt    time.Time
	codeVerifier string
	pat          string // Personal Access Token, if set, takes precedence
}

// New creates a new RMS API client using the provided Config.
func New(cfg Config) *Client {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		baseURL:      baseURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		redirectURI:  cfg.RedirectURI,
		scopes:       cfg.Scopes,
		httpClient:   &http.Client{Timeout: timeout},
		pat:          cfg.PAT,
	}
}

// SetToken allows updating the PAT token at runtime.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = token
	debug.Debug("SetToken called", "token_set", token != "")
}

// SetPAT allows setting a Personal Access Token for authentication.
func (c *Client) SetPAT(pat string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pat = pat
	debug.Debug("SetPAT called", "pat_set", pat != "")
}

// doRequest performs an HTTP request with authentication.
func (c *Client) DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	c.mu.Lock()
	pat := c.pat
	token := c.accessToken
	c.mu.Unlock()

	var reqBody []byte
	var err error
	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			debug.Debug("Failed to marshal request body", "error", err)
			return nil, err
		}
	}
	url := c.baseURL + path
	debug.Debug("Preparing HTTP request", "method", method, "url", url)
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
	if err != nil {
		debug.Debug("Failed to create HTTP request", "error", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
		debug.Debug("Using PAT for authentication")
	} else if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		debug.Debug("Using OAuth2 access token for authentication")
	} else {
		debug.Debug("No authentication token set")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		debug.Debug("HTTP request failed", "error", err)
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		debug.Debug("Failed to read response body", "error", err)
		return nil, err
	}
	if resp.StatusCode >= 400 {
		debug.Debug("RMS API error response", "status", resp.StatusCode, "body", string(respBody))
		return nil, fmt.Errorf("RMS API error: %s", respBody)
	}
	debug.Debug("HTTP request successful", "status", resp.StatusCode, "url", url)
	return respBody, nil
}

// AuthCodeURL generates the URL for the OAuth2 authorization request.
func (c *Client) AuthCodeURL(state string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate a code verifier and challenge for PKCE
	codeVerifierBytes := make([]byte, 32)
	_, err := rand.Read(codeVerifierBytes)
	if err != nil {
		debug.Debug("Failed to generate code verifier", "error", err)
		return "", err
	}
	c.codeVerifier = base64.RawURLEncoding.EncodeToString(codeVerifierBytes)

	hash := sha256.Sum256([]byte(c.codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Authorization request URL
	u, err := url.Parse(c.baseURL + AuthEndpoint)
	if err != nil {
		debug.Debug("Failed to parse AuthEndpoint URL", "error", err)
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", c.redirectURI)
	q.Set("scope", strings.Join(c.scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	debug.Debug("Generated AuthCodeURL", "url", u.String())
	return u.String(), nil
}

// ExchangeAuthCode exchanges the authorization code for an access token.
func (c *Client) ExchangeAuthCode(ctx context.Context, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	debug.Debug("Exchanging auth code for token")
	// Token request
	resp, err := c.httpClient.PostForm(c.baseURL+TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.redirectURI},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"code_verifier": {c.codeVerifier},
	})
	if err != nil {
		debug.Debug("Token request failed", "error", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		debug.Debug("Token request error response", "status", resp.StatusCode, "body", string(body))
		return fmt.Errorf("token request failed: %s", body)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		debug.Debug("Failed to decode token response", "error", err)
		return err
	}

	c.accessToken = tokenResp.AccessToken
	c.refreshToken = tokenResp.RefreshToken
	c.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	debug.Debug("Token exchange successful", "expires_in", tokenResp.ExpiresIn)
	return nil
}

// RefreshAccessToken refreshes the access token using the refresh token.
func (c *Client) RefreshAccessToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if the access token is still valid
	if time.Now().Before(c.expiresAt) {
		debug.Debug("Access token still valid", "expires_at", c.expiresAt)
		return nil
	}

	debug.Debug("Refreshing access token")
	// Token request
	resp, err := c.httpClient.PostForm(c.baseURL+TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.refreshToken},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	})
	if err != nil {
		debug.Debug("Token refresh request failed", "error", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		debug.Debug("Token refresh error response", "status", resp.StatusCode, "body", string(body))
		return fmt.Errorf("token refresh failed: %s", body)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		debug.Debug("Failed to decode token refresh response", "error", err)
		return err
	}

	c.accessToken = tokenResp.AccessToken
	c.refreshToken = tokenResp.RefreshToken
	c.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	debug.Debug("Token refresh successful", "expires_in", tokenResp.ExpiresIn)
	return nil
}
