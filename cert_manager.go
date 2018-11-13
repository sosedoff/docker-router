package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"log"
	"os"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func configureCertManager(policyFunc autocert.HostPolicy) (*autocert.Manager, error) {
	certsDir := os.Getenv("LETSENCRYPT_CERTS_DIR")
	if certsDir == "" {
		return nil, errors.New("LETSENCRYPT_CERTS_DIR env var is not set")
	}

	email := os.Getenv("LETENCRYPT_EMAIL")
	if email == "" {
		return nil, errors.New("LETENCRYPT_EMAIL env var is not set")
	}

	manager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(certsDir),
		Email:      email,
		HostPolicy: policyFunc,
	}

	// Use LetsEncrypt staging endpoint for testing purposes
	if os.Getenv("LETSENCRYPT_STAGING") != "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		manager.Client = &acme.Client{
			DirectoryURL: "https://acme-staging.api.letsencrypt.org/directory",
			Key:          key,
		}
	}

	return &manager, nil
}
