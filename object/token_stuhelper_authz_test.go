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

package object

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	beegocontext "github.com/beego/beego/v2/server/web/context"
	"github.com/golang-jwt/jwt/v5"
)

func TestStuHelperBoundAuthorizationCodeAndRefreshFlow(t *testing.T) {
	setupStuHelperOAuthTestDatabase(t)

	const (
		clientID       = "op_dynamic_refresh_test"
		clientSecret   = "test-client-secret"
		redirectURI    = "https://rp.example/callback"
		providerUserID = "test-org/provider-subject"
		binding        = "ag1:7:opaque:mac"
		nonce          = "  nonce +&=/% preserved  "
	)
	application := &Application{
		Owner:                "admin",
		Name:                 "stuhelper-dynamic-refresh",
		Organization:         "test-org",
		Cert:                 "stuhelper-refresh-cert",
		ClientId:             clientID,
		ClientSecret:         clientSecret,
		RedirectUris:         []string{redirectURI},
		GrantTypes:           []string{"authorization_code", "refresh_token"},
		TokenFormat:          "JWT-Custom",
		TokenFields:          []string{},
		ExpireInHours:        1,
		RefreshExpireInHours: 24,
	}
	if _, err := ormer.Engine.Insert(application); err != nil {
		t.Fatal(err)
	}
	if _, err := ormer.Engine.Insert(&Organization{Owner: "admin", Name: "test-org"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ormer.Engine.Insert(&User{Owner: "test-org", Name: "provider-subject", Id: providerUserID}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddCert(&Cert{
		Owner: "admin", Name: application.Cert, CryptoAlgorithm: "RS256", BitSize: 2048, ExpireInYears: 1,
	}); err != nil {
		t.Fatal(err)
	}

	code, err := GetOAuthCode(
		providerUserID, clientID, "", "password", "code", redirectURI,
		"openid profile offline_access", "state", nonce, binding, "", "", "sso.example.test", "en",
	)
	if err != nil || code == nil || code.Message != "" || code.Code == "" {
		t.Fatalf("authorization code issuance = (%#v, %v)", code, err)
	}
	issued := stuHelperOAuthTokenRequest(t, "authorization_code", clientID, clientSecret, code.Code, "", "")
	if issued.RefreshToken == "" {
		t.Fatal("offline_access authorization code did not return a refresh token")
	}
	assertStuHelperTokenClaims(t, application, issued.AccessToken, binding, nonce, "openid profile offline_access")

	refreshed := stuHelperOAuthTokenRequest(
		t, "refresh_token", clientID, clientSecret, "", "offline_access profile openid openid", issued.RefreshToken,
	)
	if refreshed.RefreshToken == "" {
		t.Fatal("eligible bound refresh did not rotate the refresh token")
	}
	assertStuHelperTokenClaims(t, application, refreshed.AccessToken, binding, "", "offline_access profile openid openid")

	changed, err := GetOAuthToken(
		"refresh_token", clientID, clientSecret, "", "", "openid offline_access", "", "", "",
		"sso.example.test", refreshed.RefreshToken, "", "", "en", "", "", "", "", "", "", "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	changedError, ok := changed.(*TokenError)
	if !ok || changedError.Error != InvalidScope {
		t.Fatalf("scope-changing bound refresh = %#v, want invalid_scope", changed)
	}

	codeWithoutOffline, err := GetOAuthCode(
		providerUserID, clientID, "", "password", "code", redirectURI,
		"openid profile", "state", nonce, binding, "", "", "sso.example.test", "en",
	)
	if err != nil || codeWithoutOffline == nil || codeWithoutOffline.Message != "" || codeWithoutOffline.Code == "" {
		t.Fatalf("ordinary authorization code issuance = (%#v, %v)", codeWithoutOffline, err)
	}
	withoutOffline := stuHelperOAuthTokenRequest(t, "authorization_code", clientID, clientSecret, codeWithoutOffline.Code, "", "")
	if withoutOffline.RefreshToken != "" {
		t.Fatal("bound authorization code without offline_access exposed a refresh token")
	}

	application.GrantTypes = []string{"authorization_code"}
	if _, err := ormer.Engine.Where("owner = ? AND name = ?", application.Owner, application.Name).Cols("grant_types").Update(application); err != nil {
		t.Fatal(err)
	}
	unsupported, err := GetOAuthToken(
		"refresh_token", clientID, clientSecret, "", "", "", "", "", "",
		"sso.example.test", refreshed.RefreshToken, "", "", "en", "", "", "", "", "", "", "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	unsupportedError, ok := unsupported.(*TokenError)
	if !ok || unsupportedError.Error != UnsupportedGrantType {
		t.Fatalf("application without refresh_token grant = %#v, want unsupported_grant_type", unsupported)
	}
}

func setupStuHelperOAuthTestDatabase(t *testing.T) {
	t.Helper()
	previous := ormer
	adapter, err := NewAdapter("sqlite", "file:"+filepath.Join(t.TempDir(), "oauth.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	ormer = adapter
	t.Cleanup(func() {
		ormer = previous
		adapter.close()
	})
	for _, bean := range []any{
		new(Application), new(Organization), new(Provider), new(User), new(Permission), new(Role), new(Token), new(Cert),
		new(ThirdPartyLink),
	} {
		if err := ormer.Engine.Sync2(bean); err != nil {
			t.Fatal(err)
		}
	}
}

func stuHelperOAuthTokenRequest(t *testing.T, grantType, clientID, clientSecret, code, scope, refreshToken string) *TokenWrapper {
	t.Helper()
	result, err := GetOAuthToken(
		grantType, clientID, clientSecret, code, "", scope, "", "", "",
		"sso.example.test", refreshToken, "", "", "en", "", "", "", "", "", "", "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, ok := result.(*TokenWrapper)
	if !ok {
		t.Fatalf("OAuth token response = %#v", result)
	}
	return wrapper
}

func assertStuHelperTokenClaims(t *testing.T, application *Application, rawToken, binding, nonce, scope string) {
	t.Helper()
	cert, err := getCertByApplication(application)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseJwtToken(rawToken, cert)
	if err != nil {
		t.Fatal(err)
	}
	if claims.StuHelperAuthz != binding || claims.Nonce != nonce || claims.Scope != scope {
		t.Fatalf("token claims = binding %q nonce %q scope %q", claims.StuHelperAuthz, claims.Nonce, claims.Scope)
	}
}

func TestStuHelperAuthorizationBindingDoesNotReplaceClientNonce(t *testing.T) {
	claims := Claims{
		User:             &User{},
		TokenType:        "access-token",
		Nonce:            " rp nonce &=+ /~._- kept byte-for-byte ",
		StuHelperAuthz:   "ag1:7:opaque:mac",
		Scope:            "openid profile",
		RegisteredClaims: jwt.RegisteredClaims{Subject: "provider-subject"},
	}

	custom := getClaimsCustom(claims, nil, nil)
	if got := custom["nonce"]; got != claims.Nonce {
		t.Fatalf("nonce = %v, want %q", got, claims.Nonce)
	}
	if got := custom["stuhelper_authz"]; got != claims.StuHelperAuthz {
		t.Fatalf("stuhelper_authz = %v, want %q", got, claims.StuHelperAuthz)
	}
	standard := getStandardClaims(claims)
	if standard.Nonce != claims.Nonce || standard.StuHelperAuthz != claims.StuHelperAuthz {
		t.Fatalf("standard claims lost independent nonce or authorization binding")
	}
}

func TestRefreshAuthorizationStateRetainsOldBindingAndRejectsScopeChangeBeforeMint(t *testing.T) {
	if got := authorizationCodeRefreshToken("bound", "openid profile", "must-not-leak"); got != "" {
		t.Fatalf("bound authorization code without offline_access returned refresh token %q", got)
	}
	if got := authorizationCodeRefreshToken("bound", "openid offline_access", "refresh"); got != "refresh" {
		t.Fatalf("bound authorization code with offline_access returned %q", got)
	}
	if got := authorizationCodeRefreshToken("", "openid", "legacy-refresh"); got != "legacy-refresh" {
		t.Fatalf("unbound authorization code behavior changed: %q", got)
	}

	scope, binding, tokenErr := refreshAuthorizationState("openid profile", "old-generation-binding", "")
	if tokenErr == nil || tokenErr.Error != InvalidGrant || scope != "" || binding != "" {
		t.Fatalf("bound refresh without offline_access = (%q, %q, %#v)", scope, binding, tokenErr)
	}
	scope, binding, tokenErr = refreshAuthorizationState("openid profile offline_access", "old-generation-binding", "offline_access profile openid openid")
	if tokenErr != nil || scope != "offline_access profile openid openid" || binding != "old-generation-binding" {
		t.Fatalf("reordered refresh state = (%q, %q, %#v)", scope, binding, tokenErr)
	}
	scope, binding, tokenErr = refreshAuthorizationState("openid profile offline_access", "old-generation-binding", "openid offline_access")
	if scope != "" || binding != "" || tokenErr == nil || tokenErr.Error != InvalidScope {
		t.Fatalf("scope-changing bound refresh did not return invalid_scope before mint: (%q, %q, %#v)", scope, binding, tokenErr)
	}
	scope, binding, tokenErr = refreshAuthorizationState("openid profile", "", "openid")
	if tokenErr != nil || scope != "openid" || binding != "" {
		t.Fatalf("ordinary unbound refresh scope narrowing regressed: (%q, %q, %#v)", scope, binding, tokenErr)
	}
}

func TestOAuthCodeRejectsOversizedStuHelperAuthorizationBinding(t *testing.T) {
	_, err := GetOAuthCode("user", "client", "", "", "code", "https://client.example/callback", "openid", "state", "nonce", strings.Repeat("x", (16<<10)+1), "", "", "example.com", "en")
	if err == nil {
		t.Fatal("expected oversized stuhelper authorization binding to be rejected")
	}
}

func TestNewRecordStructurallyRedactsStuHelperAuthorizationBinding(t *testing.T) {
	const canary = "STUHELPER_RECORD_AUTHZ_CANARY"
	for _, path := range []string{
		"/api/login",
		"/api/signup",
		"/api/device-auth-complete",
		"/api/webauthn/signin/finish",
		"/api/grant-consent",
	} {
		t.Run(path, func(t *testing.T) {
			body := `{"application":"admin/app","grantedScopes":["profile"],"ordinary":"kept","stuHelperAuthz":"` + canary + `","nested":{"stuhelper_authz":"` + canary + `"}}`
			request := httptest.NewRequest("POST", path+"?clientId=op_dynamic&stuhelper_authz="+canary, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			ctx := beegocontext.NewContext()
			ctx.Reset(httptest.NewRecorder(), request)
			ctx.Input.RequestBody = []byte(body)

			record, err := NewRecord(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(record.RequestUri, canary) || strings.Contains(record.Object, canary) {
				t.Fatalf("authorization binding entered Casdoor record: %#v", record)
			}
			if !strings.Contains(record.RequestUri, "clientId=op_dynamic") ||
				!strings.Contains(record.Object, `"ordinary":"kept"`) ||
				!strings.Contains(record.Object, `"grantedScopes":["profile"]`) {
				t.Fatalf("ordinary audit fields were not retained: %#v", record)
			}
			if strings.Contains(record.Object, "stuHelperAuthz") || strings.Contains(record.Object, "stuhelper_authz") {
				t.Fatalf("authorization binding keys were retained: %s", record.Object)
			}
		})
	}

	malformed := `{"ordinary":"kept","stuHelperAuthz":"` + canary
	request := httptest.NewRequest("POST", "/api/login", strings.NewReader(malformed))
	ctx := beegocontext.NewContext()
	ctx.Reset(httptest.NewRecorder(), request)
	ctx.Input.RequestBody = []byte(malformed)
	record, err := NewRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(record.Object, canary) || record.Object != `{"recording":"invalid_json_omitted"}` {
		t.Fatalf("malformed sensitive endpoint body was not omitted: %q", record.Object)
	}
}
