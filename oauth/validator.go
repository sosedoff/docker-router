package oauth

import (
	"github.com/mcnijman/go-emailaddress"
)

// Validator performs account validation checks
type Validator interface {
	Validate(string) bool
}

// EmailValidator performs email validation checks
type EmailValidator struct {
	AllowedEmails  map[string]struct{}
	AllowedDomains map[string]struct{}
}

// Validate returns true if email is allowed
func (v EmailValidator) Validate(email string) bool {
	if len(v.AllowedEmails) > 0 {
		if _, ok := v.AllowedEmails[email]; ok {
			return true
		}
	}

	if len(v.AllowedDomains) > 0 {
		addr, err := emailaddress.Parse(email)
		if err != nil {
			return false
		}
		if _, ok := v.AllowedDomains[addr.Domain]; ok {
			return true
		}
	}

	return false
}
