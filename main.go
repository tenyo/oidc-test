package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

const listenAddr = "127.0.0.1:5556"

type config struct {
	OAuth struct {
		IssuerURL    string `yaml:"issuerUrl"`
		ClientID     string `yaml:"clientID"`
		ClientSecret string `yaml:"clientSecret"`
	} `yaml:"oauth"`
}

type idTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

var (
	ctx         context.Context
	oauthConfig oauth2.Config
	verifier    *oidc.IDTokenVerifier
)

func main() {
	conf, err := newConfig("config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	ctx = context.Background()
	oidcConfig := &oidc.Config{
		ClientID: conf.OAuth.ClientID,
	}
	provider, err := oidc.NewProvider(ctx, conf.OAuth.IssuerURL)
	if err != nil {
		log.Fatal(err)
	}

	verifier = provider.Verifier(oidcConfig)
	oauthConfig = oauth2.Config{
		ClientID:     conf.OAuth.ClientID,
		ClientSecret: conf.OAuth.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  fmt.Sprintf("http://%s/auth/callback", listenAddr),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/", loginHandler)
	http.HandleFunc("/auth/callback", callbackHandler)

	log.Printf("listening on http://%s/", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func newConfig(configPath string) (*config, error) {
	config := &config{}

	f, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	d := yaml.NewDecoder(f)
	if err := d.Decode(config); err != nil {
		return nil, err
	}

	return config, nil
}
