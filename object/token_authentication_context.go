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
	"strings"
)

const mfaAssuranceContext = "mfa"

// AuthenticationContext is trusted token-issuance input. Controllers create
// it only after a server-side MFA verifier succeeds; it must never be decoded
// directly from a client login form.
type AuthenticationContext struct {
	AMR      []string
	AuthTime int64
	ACR      string
}

func NewMFAAuthenticationContext(signinMethod, mfaType string, verifiedAt int64) *AuthenticationContext {
	if verifiedAt <= 0 {
		return nil
	}

	mfaMethod := mfaAMRMethod(mfaType)
	if mfaMethod == "" {
		return nil
	}

	amr := make([]string, 0, 3)
	if primary := primaryAMRMethod(signinMethod); primary != "" {
		amr = append(amr, primary)
	}
	amr = append(amr, mfaAssuranceContext)
	if mfaMethod != mfaAssuranceContext {
		amr = append(amr, mfaMethod)
	}

	return &AuthenticationContext{
		AMR:      amr,
		AuthTime: verifiedAt,
		ACR:      mfaAssuranceContext,
	}
}

func authenticationContextFromClaims(amr []string, authTime int64, acr string) *AuthenticationContext {
	if authTime <= 0 || strings.TrimSpace(acr) != mfaAssuranceContext || !containsMFAAMR(amr) {
		return nil
	}
	return &AuthenticationContext{
		AMR:      append([]string(nil), amr...),
		AuthTime: authTime,
		ACR:      mfaAssuranceContext,
	}
}

// RestoreAuthenticationContext validates authentication context loaded from a
// trusted server-side session before it is used for token issuance.
func RestoreAuthenticationContext(amr []string, authTime int64, acr string) *AuthenticationContext {
	return authenticationContextFromClaims(amr, authTime, acr)
}

func containsMFAAMR(amr []string) bool {
	for _, method := range amr {
		switch strings.ToLower(strings.TrimSpace(method)) {
		case mfaAssuranceContext, "otp", "sms", "totp", "webauthn", "fido", "fido2", "hwk":
			return true
		}
	}
	return false
}

func primaryAMRMethod(signinMethod string) string {
	switch strings.ToLower(strings.TrimSpace(signinMethod)) {
	case "password", "ldap":
		return "pwd"
	case "verification code":
		return "otp"
	case "webauthn":
		return "webauthn"
	default:
		return ""
	}
}

func mfaAMRMethod(mfaType string) string {
	switch strings.ToLower(strings.TrimSpace(mfaType)) {
	case TotpType:
		return "totp"
	case SmsType:
		return "sms"
	case EmailType:
		return "otp"
	case "webauthn":
		return "webauthn"
	case RadiusType, PushType, "recovery":
		return mfaAssuranceContext
	default:
		return ""
	}
}

func authenticationTimeUnix(value *jwt.NumericDate) int64 {
	if value == nil {
		return 0
	}
	return value.Unix()
}
