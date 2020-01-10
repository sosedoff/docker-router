package config

// LetsEncryptConfig holds the certificate store configuration
type LetsEncryptConfig struct {
	Email string    `json:"email"`
	Store string    `json:"store"`
	S3    *S3Config `json:"s3"`
}

// S3Config holds the S3 configuration for certificate store
type S3Config struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
}
