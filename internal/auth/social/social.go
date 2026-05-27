package social

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Profile holds the normalized user identity returned by a social provider.
type Profile struct {
	ProviderID string
	Email      string
	Name       string
}

// AuthURL builds the OAuth2 authorization URL for the given provider.
func AuthURL(provider, clientID, redirectURI, state string) (string, error) {
	var base string
	var params url.Values
	switch provider {
	case "github":
		base = "https://github.com/login/oauth/authorize"
		params = url.Values{"client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {"user:email"}, "state": {state}}
	case "google":
		base = "https://accounts.google.com/o/oauth2/v2/auth"
		params = url.Values{"client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {"openid email profile"}, "response_type": {"code"}, "state": {state}}
	case "discord":
		base = "https://discord.com/api/oauth2/authorize"
		params = url.Values{"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"}, "scope": {"identify email"}, "state": {state}}
	default:
		return "", errors.New("unknown provider: " + provider)
	}
	return base + "?" + params.Encode(), nil
}

// ExchangeToken exchanges an OAuth2 authorization code for an access token.
func ExchangeToken(ctx context.Context, provider, clientID, clientSecret, code, redirectURI string) (string, error) {
	var tokenURL string
	switch provider {
	case "github":
		tokenURL = "https://github.com/login/oauth/access_token"
	case "google":
		tokenURL = "https://oauth2.googleapis.com/token"
	case "discord":
		tokenURL = "https://discord.com/api/oauth2/token"
	default:
		return "", errors.New("unknown provider: " + provider)
	}
	v := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Error != "" {
		return "", errors.New(result.Error)
	}
	if result.AccessToken == "" {
		return "", errors.New("no access token in response")
	}
	return result.AccessToken, nil
}

// FetchProfile retrieves the user's profile from the provider using the access token.
func FetchProfile(ctx context.Context, provider, accessToken string) (*Profile, error) {
	switch provider {
	case "github":
		return fetchGitHub(ctx, accessToken)
	case "google":
		return fetchGoogle(ctx, accessToken)
	case "discord":
		return fetchDiscord(ctx, accessToken)
	}
	return nil, errors.New("unknown provider: " + provider)
}

func apiGet(ctx context.Context, rawURL, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GateKeeper/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

func fetchGitHub(ctx context.Context, token string) (*Profile, error) {
	body, err := apiGet(ctx, "https://api.github.com/user", token)
	if err != nil {
		return nil, err
	}
	var u struct {
		ID    int    `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, err
	}
	if u.ID == 0 {
		return nil, errors.New("github: missing user id")
	}
	email := u.Email
	if email == "" {
		email = fetchGitHubEmail(ctx, token)
	}
	return &Profile{ProviderID: fmt.Sprintf("%d", u.ID), Email: email, Name: u.Login}, nil
}

func fetchGitHubEmail(ctx context.Context, token string) string {
	body, err := apiGet(ctx, "https://api.github.com/user/emails", token)
	if err != nil {
		return ""
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	json.Unmarshal(body, &emails)
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	return ""
}

func fetchGoogle(ctx context.Context, token string) (*Profile, error) {
	body, err := apiGet(ctx, "https://www.googleapis.com/oauth2/v2/userinfo", token)
	if err != nil {
		return nil, err
	}
	var u struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, err
	}
	if u.ID == "" {
		return nil, errors.New("google: missing user id")
	}
	return &Profile{ProviderID: u.ID, Email: u.Email, Name: u.Name}, nil
}

func fetchDiscord(ctx context.Context, token string) (*Profile, error) {
	body, err := apiGet(ctx, "https://discord.com/api/users/@me", token)
	if err != nil {
		return nil, err
	}
	var u struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, err
	}
	if u.ID == "" {
		return nil, errors.New("discord: missing user id")
	}
	return &Profile{ProviderID: u.ID, Email: u.Email, Name: u.Username}, nil
}
