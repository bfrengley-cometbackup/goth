package goth

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

type ErrNoSuchProvider struct {
	name string
}

func (e *ErrNoSuchProvider) Error() string {
	return fmt.Sprintf("no provider for %s exists", e.name)
}

// Provider needs to be implemented for each 3rd party authentication provider
// e.g. Facebook, Twitter, etc...
type Provider interface {
	Name() string
	SetName(name string)
	BeginAuth(state string) (Session, error)
	UnmarshalSession(string) (Session, error)
	FetchUser(Session) (User, error)
	Debug(bool)
	RefreshToken(refreshToken string) (*oauth2.Token, error) // Get new access token based on the refresh token
	RefreshTokenAvailable() bool                             // Refresh token is provided by auth provider or not
}

const NoAuthUrlErrorMessage = "an AuthURL has not been set"

// Providers is list of known/available providers.
type Providers map[string]Provider

var providerLock sync.RWMutex
var providers = Providers{}

// UseProviders adds a list of available providers for use with Goth.
// Can be called multiple times. If you pass the same provider more
// than once, the last will be used.
func UseProviders(viders ...Provider) {
	providerLock.Lock()
	defer providerLock.Unlock()

	for _, provider := range viders {
		providers[provider.Name()] = provider
	}
}

// GetProviders returns a list of all the providers currently in use.
func GetProviders() Providers {
	providerLock.RLock()
	defer providerLock.RUnlock()

	providersCopy := Providers{}
	for k, v := range providers {
		providersCopy[k] = v
	}
	return providersCopy
}

// GetProvider returns a previously created provider. If Goth has not
// been told to use the named provider it will return an error.
func GetProvider(name string) (Provider, error) {
	providerLock.RLock()
	provider := providers[name]
	providerLock.RUnlock()

	if provider == nil {
		return nil, &ErrNoSuchProvider{name}
	}
	return provider, nil
}

// RemoveProvider removes a previously created provider. If Goth has not
// been told to use the named provider it will return an error.
func RemoveProvider(name string) error {
	providerLock.Lock()
	defer providerLock.Unlock()

	if _, ok := providers[name]; !ok {
		return &ErrNoSuchProvider{name}
	}
	delete(providers, name)
	return nil
}

// ClearProviders will remove all providers currently in use.
// This is useful, mostly, for testing purposes.
func ClearProviders() {
	providerLock.Lock()
	providers = Providers{}
	providerLock.Unlock()
}

// ContextForClient provides a context for use with oauth2.
func ContextForClient(h *http.Client) context.Context {
	if h == nil {
		return oauth2.NoContext
	}
	return context.WithValue(oauth2.NoContext, oauth2.HTTPClient, h)
}

// HTTPClientWithFallBack to be used in all fetch operations.
func HTTPClientWithFallBack(h *http.Client) *http.Client {
	if h != nil {
		return h
	}
	return http.DefaultClient
}
