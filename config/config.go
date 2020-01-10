package config

import (
	"encoding/json"
	"io/ioutil"
)

// Config contains server configuration
type Config struct {
	LetsEncrypt *LetsEncryptConfig     `json:"letsencrypt"`
	OAuth       map[string]OAuthConfig `json:"oauth"`
}

// Load reads the JSON configuration from a file
func Load(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	if err := config.validateOAuth(); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) validateOAuth() error {
	for _, auth := range c.OAuth {
		if err := auth.Validate(); err != nil {
			return err
		}
	}
	return nil
}
