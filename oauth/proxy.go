package oauth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/pusher/oauth2_proxy/pkg/apis/options"
	sessionsapi "github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/sessions"
	"github.com/pusher/oauth2_proxy/providers"
)

var (
	AuthPrefix       = "/_oauth"
	AuthStartPath    = ""
	AuthCallbackPath = "/callback"
	AuthProfilePath  = "/profile"
	AuthSignoutPath  = "/signout"

	oauthCSRFCookieName    = "_oauth_csrf"
	oauthSessionCookieName = "_oauth_session"

	errStateNotFound = errors.New("State not found")
	errAuthRequired  = errors.New("Authentication required")
	errHaltChain     = errors.New("Chain halted")
)

type Proxy struct {
	Provider     providers.Provider
	SecureCookie securecookie.SecureCookie
	Store        sessionsapi.SessionStore
	Log          *Logger
	Validator    Validator

	StartPath    string
	CallbackPath string
	ProfilePath  string
	SignoutPath  string
}

type Context struct {
	Host           string
	Scheme         string
	ResponseWriter http.ResponseWriter
	Request        *http.Request
}

type Logger struct {
	*log.Logger

	id       string
	provider string
}

func (l *Logger) Println(args ...interface{}) {
	newargs := make([]string, len(args))
	for i, arg := range args {
		newargs[i] = fmt.Sprintf("%s", arg)
	}

	l.Printf("oauth=%q provider=%q message=%q", l.id, l.provider, strings.Join(newargs, " "))
}

func (ctx *Context) Fail(message string) {
	http.Error(ctx.ResponseWriter, message, 400)
}

// handleStart starts the OAuth authentication flow
func (p *Proxy) Start(ctx *Context) {
	// Generate a new nonce and set CSRF cookie for the OAuth flow
	nonce, err := p.generateNonce()
	if err != nil {
		p.Log.Println("Nonce generation failed:", err)
		ctx.Fail(err.Error())
		return
	}
	p.setCSRFCookie(ctx, nonce)

	// Prepare callback and redirect URLs
	callbackURL := p.makeRedirectURL(ctx, p.CallbackPath)
	finalURL := p.makeRedirectURL(ctx, ctx.Request.URL.Path)
	loginURL := fmt.Sprintf("%v:%v", nonce, finalURL)

	// Initiate OAuth
	http.Redirect(
		ctx.ResponseWriter,
		ctx.Request,
		p.Provider.GetLoginURL(callbackURL, loginURL),
		302,
	)
}

// handleCallback handles the OAuth callback request
func (p *Proxy) Callback(ctx *Context) {
	// Parse the incoming form data
	if err := ctx.Request.ParseForm(); err != nil {
		p.Log.Println("Form parse error:", err)
		ctx.Fail("Invalid form data")
		return
	}
	form := ctx.Request.Form

	// Terminate the chain if OAuth error is received
	if errMsg := form.Get("error"); errMsg != "" {
		p.Log.Println("OAuth error:", errMsg)
		ctx.Fail(errMsg)
		return
	}

	// Get the auth token
	code := form.Get("code")
	if code == "" {
		p.Log.Println("Code param is not provided")
		ctx.Fail("Invalid code param")
		return
	}

	// Get the state
	state := strings.SplitN(form.Get("state"), ":", 2)
	if len(state) != 2 {
		p.Log.Println("State param is not valid")
		ctx.Fail("Invalid state param")
		return
	}
	nonce := state[0]
	targetURL := state[1]

	// Redeem auth token
	session, err := p.Provider.Redeem(p.makeRedirectURL(ctx, p.CallbackPath), code)
	if err != nil {
		p.Log.Println("Token redeem error:", err)
		ctx.Fail("Token redeem error")
		return
	}

	// Fetch details
	if session.User == "" {
		if user, err := p.Provider.GetUserName(session); err == nil {
			session.User = user
		} else {
			p.Log.Println("Username fetch error:", err)
		}
	}
	if session.Email == "" {
		if email, err := p.Provider.GetEmailAddress(session); err == nil {
			session.Email = email
		} else {
			p.Log.Println("Email fetch error:", err)
		}
	}

	// Validate CSRF cookie
	csrfCookie, err := ctx.Request.Cookie(oauthCSRFCookieName)
	p.clearCSRFCookie(ctx)
	if err != nil {
		p.Log.Println("CSRF cookie fetch error:", err)
		ctx.Fail("Invalid CSRF cookie")
		return
	}
	if csrfCookie.Value != nonce {
		p.Log.Println("Invalid CSRF cookie")
		ctx.Fail("CSRF Cookie does not match")
		return
	}

	if !(p.Validator.Validate(session.Email) && p.Provider.ValidateGroup(session.Email)) {
		p.Log.Println("Validation error for user:", session.Email)
		ctx.Fail("Permission Denied")
		return
	}

	// Save the session
	if err := p.Store.Save(ctx.ResponseWriter, ctx.Request, session); err != nil {
		p.Log.Println("Session save error:", err)
		ctx.Fail("Failed to save the session")
		return
	}

	// Redirect to the final destination
	http.Redirect(ctx.ResponseWriter, ctx.Request, targetURL, 302)
}

// handleProfile displays the current OAuth session details
func (p *Proxy) Profile(ctx *Context) {
	state, err := p.Store.Load(ctx.Request)
	if err != nil {
		p.Log.Println("Session load error:", err)
		ctx.Fail("Current session is not valid!")
		return
	}
	json.NewEncoder(ctx.ResponseWriter).Encode(map[string]interface{}{
		"user":  state.User,
		"email": state.Email,
	})
}

// handleSignout removes OAuth authentication
func (p *Proxy) Signout(ctx *Context) {
	if err := p.cleanSession(ctx); err != nil {
		p.Log.Println("Auth session cleanup error:", err)
	}
	http.Redirect(ctx.ResponseWriter, ctx.Request, "/", 302)
}

func (p *Proxy) makeRedirectURL(ctx *Context, path string) string {
	return fmt.Sprintf("%s://%s%s", ctx.Scheme, ctx.Host, path)
}

// makeCookie returns a new cookie for the auth context
func (p *Proxy) makeCookie(ctx *Context, name string, value string, expiration time.Duration, now time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   ctx.Host,
		HttpOnly: true,
		Secure:   false,
		Expires:  now.Add(expiration),
	}
}

// setCSRFCookie sets a CSRF cookie for OAuth flow
func (p *Proxy) setCSRFCookie(ctx *Context, val string) {
	http.SetCookie(ctx.ResponseWriter, p.makeCookie(ctx, oauthCSRFCookieName, val, time.Minute*5, time.Now()))
}

// clearCSRFCookie removes the CSRF cookie
func (p *Proxy) clearCSRFCookie(ctx *Context) {
	http.SetCookie(ctx.ResponseWriter, p.makeCookie(ctx, oauthCSRFCookieName, "", time.Hour*-1, time.Now()))
}

// getAuthenticatedSession returns currently authenticated session
func (p *Proxy) Session(ctx *Context) (*sessionsapi.SessionState, error) {
	session, err := p.Store.Load(ctx.Request)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, errStateNotFound
	}

	// Attempt to refresh the token if it's still active
	if _, err := p.Provider.RefreshSessionIfNeeded(session); err != nil {
		p.Log.Println("Removing session", session)
		return nil, p.cleanSession(ctx)
	}

	// Terminate session if token has expired
	if session.IsExpired() {
		p.Log.Println("Removing expired session:", session)
		return nil, p.cleanSession(ctx)
	}

	// Validate user
	if !(p.Validator.Validate(session.Email) && p.Provider.ValidateGroup(session.Email)) {
		p.Log.Println("User is not allowed:", session)
		return nil, p.cleanSession(ctx)
	}

	return session, nil
}

// cleanSession removes authenticated session
func (p *Proxy) cleanSession(ctx *Context) error {
	if err := p.Store.Clear(ctx.ResponseWriter, ctx.Request); err != nil {
		return err
	}
	return errAuthRequired
}

// generateNonce returns a new random nonce string
func (p *Proxy) generateNonce() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func configureSessionStore() (sessionsapi.SessionStore, error) {
	sessionOpts := options.SessionOptions{
		Type: "cookie",
	}

	cookieOpts := options.CookieOptions{
		CookieName:     oauthSessionCookieName,
		CookieSecure:   false,
		CookieSecret:   string(securecookie.GenerateRandomKey(64)),
		CookieHTTPOnly: true,
		CookieExpire:   time.Hour * 168,
		CookieRefresh:  time.Duration(0),
		CookiePath:     "/",
	}

	return sessions.NewSessionStore(&sessionOpts, &cookieOpts)
}
