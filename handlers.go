package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	setCallbackCookie(w, r, "state", state)
	setCallbackCookie(w, r, "nonce", nonce)

	http.Redirect(w, r, oauthConfig.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("received callback")

	state, err := r.Cookie("state")
	if err != nil {
		msg := "state not found"
		log.Println(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != state.Value {
		msg := "state did not match"
		log.Println(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	oauth2Token, err := oauthConfig.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nonce, err := r.Cookie("nonce")
	if err != nil {
		msg := "nonce not found"
		log.Println(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	if idToken.Nonce != nonce.Value {
		msg := "nonce did not match"
		log.Println(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	oauth2Token.AccessToken = "*REDACTED*"

	var claims *idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *idTokenClaims
	}{oauth2Token, claims}

	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("got token %v", string(data))
	w.Write(data)
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}
