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
	}
}

// SetToken allows updating the PAT token at runtime.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = token
}

// doRequest performs an HTTP request with authentication.
func (c *Client) DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	c.mu.Lock()
	token := c.accessToken
	c.mu.Unlock()

	var reqBody []byte
	var err error
	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("RMS API error: %s", respBody)
	}
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
		return "", err
	}
	c.codeVerifier = base64.RawURLEncoding.EncodeToString(codeVerifierBytes)

	hash := sha256.Sum256([]byte(c.codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Authorization request URL
	u, err := url.Parse(c.baseURL + AuthEndpoint)
	if err != nil {
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

	return u.String(), nil
}

// ExchangeAuthCode exchanges the authorization code for an access token.
func (c *Client) ExchangeAuthCode(ctx context.Context, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

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
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token request failed: %s", body)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return err
	}

	c.accessToken = tokenResp.AccessToken
	c.refreshToken = tokenResp.RefreshToken
	c.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return nil
}

// RefreshAccessToken refreshes the access token using the refresh token.
func (c *Client) RefreshAccessToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if the access token is still valid
	if time.Now().Before(c.expiresAt) {
		return nil
	}

	// Token request
	resp, err := c.httpClient.PostForm(c.baseURL+TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.refreshToken},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token refresh failed: %s", body)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return err
	}

	c.accessToken = tokenResp.AccessToken
	c.refreshToken = tokenResp.RefreshToken
	c.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return nil
}
