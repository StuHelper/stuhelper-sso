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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	saml2types "github.com/russellhaering/gosaml2/types"
)

func TestMemorySamlRequestStoreIsSingleUse(t *testing.T) {
	store := newMemorySamlRequestStore()
	now := time.Date(2026, time.August, 18, 8, 0, 0, 0, time.UTC)
	state := NewSamlRequestState("session", "admin/provider", "relay", now)

	if err := store.Store("request", state); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	loaded, ok, err := store.Load("request")
	if err != nil || !ok || !SameSamlRequestState(loaded, state) {
		t.Fatalf("Load() = %#v, %v, %v", loaded, ok, err)
	}
	consumed, ok, err := store.LoadAndDelete("request")
	if err != nil || !ok || !SameSamlRequestState(consumed, state) {
		t.Fatalf("first LoadAndDelete() = %#v, %v, %v", consumed, ok, err)
	}
	if _, ok, err = store.LoadAndDelete("request"); err != nil || ok {
		t.Fatalf("replayed LoadAndDelete() ok = %v, error = %v", ok, err)
	}
}

func TestValidateSamlRequestStateBindsSessionProviderRelayAndExpiry(t *testing.T) {
	now := time.Date(2026, time.August, 18, 8, 0, 0, 0, time.UTC)
	state := NewSamlRequestState("session", "admin/provider", "relay", now)

	if err := ValidateSamlRequestState(state, "session", "admin/provider", "relay", now.Add(time.Minute)); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
	tests := []struct {
		name       string
		sessionId  string
		providerId string
		relayState string
		at         time.Time
	}{
		{name: "session", sessionId: "other", providerId: "admin/provider", relayState: "relay", at: now},
		{name: "provider", sessionId: "session", providerId: "admin/other", relayState: "relay", at: now},
		{name: "relay", sessionId: "session", providerId: "admin/provider", relayState: "other", at: now},
		{name: "expiry", sessionId: "session", providerId: "admin/provider", relayState: "relay", at: now.Add(SamlRequestTTL)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateSamlRequestState(state, test.sessionId, test.providerId, test.relayState, test.at); err == nil {
				t.Fatal("mismatched SAML request state was accepted")
			}
		})
	}
}

func TestMemorySamlRequestStoreRejectsDuplicateAndExpiresEntries(t *testing.T) {
	store := newMemorySamlRequestStore()
	now := time.Date(2026, time.August, 18, 8, 0, 0, 0, time.UTC)
	state := NewSamlRequestState("session", "admin/provider", "relay", now)

	if err := store.Store("request", state); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	if err := store.Store("request", state); err == nil {
		t.Fatal("duplicate request ID was accepted")
	}
	store.DeleteExpired(now.Add(SamlRequestTTL))
	if _, ok, err := store.Load("request"); err != nil || ok {
		t.Fatalf("expired entry remains: ok = %v, error = %v", ok, err)
	}
}

func TestGetSamlResponseRequestIdRequiresCorrelation(t *testing.T) {
	encode := func(xml string) string {
		return url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(xml)))
	}
	response := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response" InResponseTo="request" Version="2.0"></samlp:Response>`
	requestId, err := GetSamlResponseRequestId(encode(response))
	if err != nil || requestId != "request" {
		t.Fatalf("GetSamlResponseRequestId() = %q, %v", requestId, err)
	}

	uncorrelated := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response" Version="2.0"></samlp:Response>`
	if _, err = GetSamlResponseRequestId(encode(uncorrelated)); err == nil {
		t.Fatal("response without InResponseTo was accepted")
	}
	if _, err = GetSamlResponseRequestId("not-base64"); err == nil {
		t.Fatal("invalid response encoding was accepted")
	}
}

func TestValidateSamlAssertionRequestIdsUsesSignedSubjectConfirmation(t *testing.T) {
	assertions := []saml2types.Assertion{{
		Subject: &saml2types.Subject{
			SubjectConfirmation: &saml2types.SubjectConfirmation{
				SubjectConfirmationData: &saml2types.SubjectConfirmationData{InResponseTo: "request"},
			},
		},
	}}
	if err := validateSamlAssertionRequestIds(assertions, "request"); err != nil {
		t.Fatalf("matching signed assertion correlation rejected: %v", err)
	}
	if err := validateSamlAssertionRequestIds(assertions, "other"); err == nil {
		t.Fatal("mismatched signed assertion correlation accepted")
	}
	if err := validateSamlAssertionRequestIds(nil, "request"); err == nil {
		t.Fatal("missing signed assertion correlation accepted")
	}
}

func TestRedisSamlRequestStoreHashesUntrustedRequestId(t *testing.T) {
	store := &redisSamlRequestStore{}
	requestId := "untrusted/request:id:" + strings.Repeat("x", 4096)
	digest := sha256.Sum256([]byte(requestId))
	want := samlRequestRedisPrefix + hex.EncodeToString(digest[:])
	if got := store.key(requestId); got != want {
		t.Fatalf("key() = %q, want %q", got, want)
	}
	if strings.Contains(store.key(requestId), requestId) {
		t.Fatal("Redis key contains the untrusted request ID")
	}
}
