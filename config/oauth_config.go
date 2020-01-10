package config

import "errors"

var (
	errProviderRequired       = errors.New("Provider is not provided")
	errClientIDRequired       = errors.New("Client ID is not provided")
	errClientSecretRequired   = errors.New("Client secret is not provided")
	errAllowedDomainsRequired = errors.New("Allowed domains is not provided")
)

// OAuthConfig contains authentication parameters
type OAuthConfig struct {
	Provider       string   `json:"provider"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	AllowedDomains []string `json:"allowed_domains"`
	AllowedEmails  []string `json:"allowed_emails"`
	Disabled       bool     `json:"disabled"`
	PathPrefix     string   `json:"path_prefix"`
	SkipPaths      []string `json:"skip_paths"`
}

// Validate returns an error if config is not valid
func (c OAuthConfig) Validate() error {
	if c.Provider == "" {
		return errProviderRequired
	}
	if c.ClientID == "" {
		return errClientIDRequired
	}
	if c.ClientSecret == "" {
		return errClientSecretRequired
	}

	if c.Provider == "google" {
		if len(c.AllowedDomains) == 0 && len(c.AllowedEmails) == 0 {
			return errAllowedDomainsRequired
		}
	}

	return nil
}
