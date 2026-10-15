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
	"github.com/golang-jwt/jwt/v5"
	"reflect"
	"testing"
	"time"
)

func TestNewMFAAuthenticationContext(t *testing.T) {
	context := NewMFAAuthenticationContext("Password", TotpType, 1712345678)
	if context == nil {
		t.Fatal("expected MFA authentication context")
	}
	if !reflect.DeepEqual(context.AMR, []string{"pwd", "mfa", "totp"}) {
		t.Fatalf("unexpected AMR: %#v", context.AMR)
	}
	if context.AuthTime != 1712345678 || context.ACR != "mfa" {
		t.Fatalf("unexpected authentication context: %#v", context)
	}
}

func TestNewMFAAuthenticationContextRejectsUnverifiedOrUnknownMethod(t *testing.T) {
	if got := NewMFAAuthenticationContext("Password", TotpType, 0); got != nil {
		t.Fatalf("expected zero verification time to fail closed: %#v", got)
	}
	if got := NewMFAAuthenticationContext("Password", "client-supplied", 1712345678); got != nil {
		t.Fatalf("expected unknown MFA method to fail closed: %#v", got)
	}
}

func TestRestoreAuthenticationContextValidatesProof(t *testing.T) {
	got := RestoreAuthenticationContext([]string{"pwd", "totp"}, 1712345678, "mfa")
	if got == nil {
		t.Fatal("expected valid authentication context to be restored")
	}
	if !reflect.DeepEqual(got.AMR, []string{"pwd", "totp"}) || got.AuthTime != 1712345678 || got.ACR != "mfa" {
		t.Fatalf("restored authentication context changed the original proof: %#v", got)
	}
	for _, test := range []struct {
		name     string
		amr      []string
		authTime int64
		acr      string
	}{
		{name: "missing mfa method", amr: []string{"pwd"}, authTime: 1712345678, acr: "mfa"},
		{name: "missing auth time", amr: []string{"totp"}, acr: "mfa"},
		{name: "missing assurance context", amr: []string{"totp"}, authTime: 1712345678},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := RestoreAuthenticationContext(test.amr, test.authTime, test.acr); got != nil {
				t.Fatalf("expected proof to fail closed: %#v", got)
			}
		})
	}
}

func TestJWTProjectionsOmitMFAClaimsWithoutVerifiedContext(t *testing.T) {
	claims := Claims{User: &User{Owner: "example", Name: "alice", Id: "subject-1"}}

	short := getShortClaims(claims)
	withoutThirdIDP := getClaimsWithoutThirdIdp(claims)
	standard := getStandardClaims(claims)
	custom := getClaimsCustom(claims, nil, nil)

	for name, projection := range map[string]struct {
		amr      []string
		authTime int64
		acr      string
	}{
		"short":             {short.AMR, authenticationTimeUnix(short.AuthTime), short.ACR},
		"without third idp": {withoutThirdIDP.AMR, authenticationTimeUnix(withoutThirdIDP.AuthTime), withoutThirdIDP.ACR},
		"standard":          {standard.AMR, authenticationTimeUnix(standard.AuthTime), standard.ACR},
	} {
		t.Run(name, func(t *testing.T) {
			if len(projection.amr) != 0 || projection.authTime != 0 || projection.acr != "" {
				t.Fatalf("unverified login gained MFA claims: %#v", projection)
			}
		})
	}
	for _, claim := range []string{"amr", "auth_time", "acr"} {
		if _, ok := custom[claim]; ok {
			t.Fatalf("unverified custom JWT gained %s: %#v", claim, custom)
		}
	}
}

func TestMFAClaimsSurviveEveryJWTProjection(t *testing.T) {
	claims := Claims{
		User:              &User{Owner: "example", Name: "alice", Id: "subject-1"},
		AMR:               []string{"pwd", "mfa", "totp"},
		OidcIdTokenClaims: OidcIdTokenClaims{AuthTime: jwt.NewNumericDate(time.Unix(1712345678, 0))},
		ACR:               "mfa",
	}

	short := getShortClaims(claims)
	withoutThirdIDP := getClaimsWithoutThirdIdp(claims)
	standard := getStandardClaims(claims)
	custom := getClaimsCustom(claims, nil, nil)

	for name, projection := range map[string]struct {
		amr      []string
		authTime int64
		acr      string
	}{
		"short":             {short.AMR, authenticationTimeUnix(short.AuthTime), short.ACR},
		"without third idp": {withoutThirdIDP.AMR, authenticationTimeUnix(withoutThirdIDP.AuthTime), withoutThirdIDP.ACR},
		"standard":          {standard.AMR, authenticationTimeUnix(standard.AuthTime), standard.ACR},
	} {
		t.Run(name, func(t *testing.T) {
			if !reflect.DeepEqual(projection.amr, claims.AMR) || projection.authTime != authenticationTimeUnix(claims.AuthTime) || projection.acr != claims.ACR {
				t.Fatalf("MFA claims were dropped: %#v", projection)
			}
		})
	}
	if !reflect.DeepEqual(custom["amr"], claims.AMR) || custom["auth_time"] != claims.AuthTime || custom["acr"] != claims.ACR {
		t.Fatalf("custom JWT projection dropped MFA claims: %#v", custom)
	}
}
