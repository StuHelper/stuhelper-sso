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

import "testing"

func TestOIDCMFARequested(t *testing.T) {
	for _, value := range []string{"mfa", "urn:example:loa mfa", " MFA "} {
		if !oidcMFARequested(value) {
			t.Fatalf("expected %q to request MFA", value)
		}
	}
	for _, value := range []string{"", "pwd", "urn:example:loa"} {
		if oidcMFARequested(value) {
			t.Fatalf("did not expect %q to request MFA", value)
		}
	}
}

func TestOIDCReauthenticationParameters(t *testing.T) {
	tests := []struct {
		name                string
		prompt, maxAge, acr string
		want                bool
	}{
		{name: "prompt login", prompt: "consent login", want: true},
		{name: "zero max age", maxAge: "0", want: true},
		{name: "mfa assurance", acr: "urn:example:loa mfa", want: true},
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
