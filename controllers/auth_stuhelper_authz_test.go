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

package controllers

import (
	"net/http/httptest"
	"net/url"
	"testing"

	beegocontext "github.com/beego/beego/v2/server/web/context"
)

func TestWebAuthnSharedHandleLoggedInPathPreservesNonceAndAuthorizationBinding(t *testing.T) {
	const state = " rp state &=+ /~._- kept byte-for-byte "
	const nonce = " rp nonce &=+ /~._- kept byte-for-byte "
	const binding = "ag1:7:opaque:mac"
	query := url.Values{
		"clientId":              {"op_dynamic-client"},
		"responseType":          {ResponseTypeCode},
		"redirectUri":           {"https://client.example/callback"},
		"scope":                 {"openid profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"stuhelper_authz":       {binding},
		"code_challenge":        {"0123456789abcdef0123456789abcdef0123456789A"},
		"code_challenge_method": {"S256"},
	}
	request := httptest.NewRequest("POST", "/api/webauthn/signin/finish?"+query.Encode(), nil)
	ctx := beegocontext.NewContext()
	ctx.Reset(httptest.NewRecorder(), request)
	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "WebAuthnSigninFinish", controller)

	got := controller.oauthCodeRequestParametersFromContext()

	if got.nonce != nonce {
		t.Fatalf("WebAuthn shared login nonce = %q, want %q", got.nonce, nonce)
	}
	if got.state != state {
		t.Fatalf("WebAuthn shared login state = %q, want %q", got.state, state)
	}
	if got.stuHelperAuthz != binding {
		t.Fatalf("WebAuthn shared login binding = %q, want %q", got.stuHelperAuthz, binding)
	}
	if got.clientID != "op_dynamic-client" || got.responseType != ResponseTypeCode {
		t.Fatalf("WebAuthn shared OAuth request identity was not preserved: %#v", got)
	}
}
