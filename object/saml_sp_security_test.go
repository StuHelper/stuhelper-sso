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
	"testing"

	saml2 "github.com/russellhaering/gosaml2"
)

func TestBuildSpBindsAudienceToServiceProvider(t *testing.T) {
	setupStuHelperOAuthTestDatabase(t)
	_, err := AddCert(&Cert{Owner: "admin", Name: "cert-built-in", CryptoAlgorithm: "RS256", BitSize: 2048, ExpireInYears: 1})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := getCert("admin", "cert-built-in")
	if err != nil || cert == nil {
		t.Fatalf("synthetic certificate missing: %v", err)
	}

	sp, err := buildSp(&Provider{IdP: cert.Certificate}, "", "sso.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if sp.AudienceURI != sp.ServiceProviderIssuer || sp.AudienceURI != "https://sso.example.com/api/acs" {
		t.Fatalf("SAML audience is not bound to the service provider: audience=%q issuer=%q", sp.AudienceURI, sp.ServiceProviderIssuer)
	}
}

func TestValidateSamlAssertionWarningsFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		warnings *saml2.WarningInfo
	}{
		{name: "missing validation result"},
		{name: "invalid time", warnings: &saml2.WarningInfo{InvalidTime: true}},
		{name: "wrong audience", warnings: &saml2.WarningInfo{NotInAudience: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateSamlAssertionWarnings(test.warnings); err == nil {
				t.Fatal("expected invalid assertion warnings to be rejected")
			}
		})
	}

	if err := validateSamlAssertionWarnings(&saml2.WarningInfo{}); err != nil {
		t.Fatalf("expected a valid assertion warning set to pass: %v", err)
	}
}
