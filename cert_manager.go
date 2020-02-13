package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"os"

	s3cache "github.com/danilobuerger/autocert-s3-cache"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func testCertCache(cache autocert.Cache) error {
	testfile := fmt.Sprintf("_test_%s", uuid.NewV4().String())

	log.Println("Testing cache store write")
	if err := cache.Put(context.Background(), testfile, []byte("This is a test")); err != nil {
		return err
	}

	log.Println("Testing cache store read")
	if _, err := cache.Get(context.Background(), testfile); err != nil {
		return err
	}

	log.Println("Testing cache store delete")
	if err := cache.Delete(context.Background(), testfile); err != nil {
		return err
	}

	return nil
}

func configureCertStore() (autocert.Cache, error) {
	if dir := os.Getenv("LETSENCRYPT_CERTS_DIR"); dir != "" {
		cache := autocert.DirCache(dir)
		return cache, testCertCache(cache)
	}

	if bucket := os.Getenv("LETSENCRYPT_S3_BUCKET"); bucket != "" {
		region := os.Getenv("LETSENCRYPT_S3_REGION")
		if region == "" {
			region = "us-east-1"
		}

		cache, err := s3cache.New(region, bucket)
		if err != nil {
			return nil, err
		}
		cache.Prefix = os.Getenv("LETSENCRYPT_S3_PREFIX")

		return cache, testCertCache(cache)
	}

	return nil, errors.New("LETSENCRYPT_CERTS_DIR environment variable is required")
}

func configureCertManager(policyFunc autocert.HostPolicy) (*autocert.Manager, error) {
	email := os.Getenv("LETSENCRYPT_EMAIL")
	if email == "" {
		return nil, errors.New("LETSENCRYPT_EMAIL env var is not set")
	}

	cache, err := configureCertStore()
	if err != nil {
		return nil, err
	}

	manager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		Email:      email,
		HostPolicy: policyFunc,
	}

	if os.Getenv("LETSENCRYPT_STAGING") != "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		manager.Client = &acme.Client{
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			Key:          key,
		}
	}

	return &manager, nil
}
