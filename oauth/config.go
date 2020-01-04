package oauth

import (
	"log"
	"net/url"
	"os"
	"path/filepath"

	"github.com/pusher/oauth2_proxy/providers"

	"github.com/sosedoff/docker-router/config"
)

func Init(cfg *config.Config) (map[string]*Proxy, error) {
	result := map[string]*Proxy{}

	for id, settings := range cfg.OAuth {
		switch settings.Provider {
		case "google":
			if p, err := setupGoogleProxy(id, settings); err != nil {
				return nil, err
			} else {
				result[id] = p
			}
		}
	}

	return result, nil
}

func setupGoogleProxy(id string, c config.OAuthConfig) (*Proxy, error) {
	emptyURL := &url.URL{}

	data := providers.ProviderData{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		LoginURL:     emptyURL,
		RedeemURL:    emptyURL,
		ValidateURL:  emptyURL,
	}

	sessionStore, err := configureSessionStore()
	if err != nil {
		return nil, err
	}

	validator := EmailValidator{
		AllowedDomains: map[string]struct{}{},
		AllowedEmails:  map[string]struct{}{},
	}

	for _, email := range c.AllowedEmails {
		validator.AllowedEmails[email] = struct{}{}
	}

	for _, domain := range c.AllowedDomains {
		validator.AllowedDomains[domain] = struct{}{}
	}

	pathPrefix := c.PathPrefix
	if pathPrefix == "" {
		pathPrefix = AuthPrefix
	}

	proxy := &Proxy{
		Store:     sessionStore,
		Provider:  providers.NewGoogleProvider(&data),
		Validator: validator,
		Log: &Logger{
			Logger:   log.New(os.Stdout, "", log.LstdFlags),
			id:       id,
			provider: c.Provider,
		},
		StartPath:    filepath.Join(pathPrefix, AuthStartPath),
		CallbackPath: filepath.Join(pathPrefix, AuthCallbackPath),
		ProfilePath:  filepath.Join(pathPrefix, AuthProfilePath),
		SignoutPath:  filepath.Join(pathPrefix, AuthSignoutPath),
	}

	return proxy, nil
}
