---
title: OIDC client examples
description: Code examples for connecting applications to GateKeeper as an OIDC provider.
---

These examples show how to connect applications to GateKeeper using the OIDC (OpenID Connect) protocol. All examples use the authorization code flow with PKCE.

Before connecting a client, register it in the admin panel at `/clients`. You'll need the client ID, client secret, and allowed redirect URIs.

## Discovery URL

All OIDC clients should use GateKeeper's discovery URL for auto-configuration:

```
https://auth.example.com/.well-known/openid-configuration
```

## Python (authlib + Flask)

```python
from flask import Flask, redirect, url_for, session
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'your-flask-secret'

oauth = OAuth(app)
gatekeeper = oauth.register(
    name='gatekeeper',
    server_metadata_url='https://auth.example.com/.well-known/openid-configuration',
    client_id='myapp',
    client_secret='your-client-secret',
    client_kwargs={
        'scope': 'openid email profile',
        'code_challenge_method': 'S256',
    },
)

@app.route('/login')
def login():
    return gatekeeper.authorize_redirect(url_for('callback', _external=True))

@app.route('/callback')
def callback():
    token = gatekeeper.authorize_access_token()
    userinfo = token.get('userinfo')
    session['user'] = userinfo
    return redirect('/')
```

## Go (coreos/go-oidc)

```go
package main

import (
    "context"
    "net/http"

    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
)

var (
    provider, _ = oidc.NewProvider(context.Background(), "https://auth.example.com")
    config      = oauth2.Config{
        ClientID:     "myapp",
        ClientSecret: "your-client-secret",
        Endpoint:     provider.Endpoint(),
        RedirectURL:  "https://myapp.example.com/callback",
        Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
    }
    verifier = provider.Verifier(&oidc.Config{ClientID: "myapp"})
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
    verifier := oauth2.GenerateVerifier()
    // store verifier in session
    http.Redirect(w, r, config.AuthCodeURL("state", oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
    // retrieve verifier from session
    token, _ := config.Exchange(r.Context(), r.URL.Query().Get("code"),
        oauth2.VerifierOption(verifier))
    rawIDToken, _ := token.Extra("id_token").(string)
    idToken, _ := verifier.Verify(r.Context(), rawIDToken)
    var claims struct{ Email string `json:"email"` }
    idToken.Claims(&claims)
    // claims.Email is now the user's email
}
```

## Node.js (openid-client)

```javascript
import { Issuer } from 'openid-client';

const issuer = await Issuer.discover('https://auth.example.com');
const client = new issuer.Client({
  client_id: 'myapp',
  client_secret: 'your-client-secret',
  redirect_uris: ['https://myapp.example.com/callback'],
  response_types: ['code'],
});

// Generate PKCE values
const code_verifier = generators.codeVerifier();
const code_challenge = generators.codeChallenge(code_verifier);

// Authorization URL
const authUrl = client.authorizationUrl({
  scope: 'openid email profile',
  code_challenge,
  code_challenge_method: 'S256',
});

// Token exchange (in callback handler)
const params = client.callbackParams(req);
const tokenSet = await client.callback(
  'https://myapp.example.com/callback',
  params,
  { code_verifier }
);
const userinfo = await client.userinfo(tokenSet.access_token);
```

## Real applications

For a complete walkthrough with a real application, including mobile sign-in, see [Immich](/integrations/immich).
