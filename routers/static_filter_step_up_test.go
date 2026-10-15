// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package routers

import (
	"net/url"
	"strings"
	"testing"
)

func TestOIDCReauthenticationParameters(t *testing.T) {
	tests := []struct {
		name                string
		prompt, maxAge, acr string
		want                bool
	}{
		{name: "prompt login", prompt: "consent login", want: true},
		{name: "zero max age", maxAge: "0", want: true},
		{name: "mfa assurance", acr: "mfa", want: true},
		{name: "ordinary authorize", prompt: "consent", maxAge: "3600", acr: "pwd", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := oidcReauthenticationParameters(test.prompt, test.maxAge, test.acr); got != test.want {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestAutoSigninRedirectPreservesOpaqueState(t *testing.T) {
	const state = "  opaque +&=/% state  "
	const code = "code+&=/"
	redirect := buildOAuthCodeRedirectURL("https://rp.example/callback?existing=value", "&", code, state, "https://sso.example")
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("state"); got != state {
		t.Fatalf("state = %q, want byte-preserved %q", got, state)
	}
	if got := parsed.Query().Get("code"); got != code {
		t.Fatalf("code = %q, want %q", got, code)
	}
	if parsed.Query().Get("iss") != "https://sso.example" {
		t.Fatal("OIDC issuer missing")
	}
	if got := parsed.Query().Get("existing"); got != "value" {
		t.Fatalf("existing query = %q, want value", got)
	}
	if strings.Contains(redirect, "&state="+state) {
		t.Fatalf("opaque state was interpolated without query encoding: %q", redirect)
	}
}
