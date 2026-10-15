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

import "testing"

func requiredAccountSetupApplication() *Application {
	return &Application{EnableSignUp: true, SignupItems: []*SignupItem{
		{Name: "Username", Visible: true, Prompted: true, Regex: `^[A-Za-z][A-Za-z0-9]{4,19}$`},
		{Name: "Phone", Visible: true, Prompted: true},
	}}
}

func TestNeedsRequiredAccountSetup(t *testing.T) {
	application := requiredAccountSetupApplication()
	tests := []struct {
		name string
		user *User
		want bool
	}{
		{name: "complete", user: &User{Name: "ValidUser1", Phone: "13800138000"}, want: false},
		{name: "missing phone", user: &User{Name: "ValidUser1"}, want: true},
		{name: "legacy username", user: &User{Name: "bad_name", Phone: "13800138000"}, want: true},
		{name: "nil user", user: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := application.NeedsRequiredAccountSetup(tt.user); got != tt.want {
				t.Fatalf("NeedsRequiredAccountSetup() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNeedsRequiredAccountSetupSkipsApplicationsWithoutSignup(t *testing.T) {
	application := requiredAccountSetupApplication()
	application.EnableSignUp = false
	if application.NeedsRequiredAccountSetup(&User{Name: "ValidUser1"}) {
		t.Fatal("an application without signup must not enforce signup fields")
	}
}

func TestRequiredUsernameChangeIsOneTimeByConstruction(t *testing.T) {
	application := requiredAccountSetupApplication()
	legacy := &User{Name: "bad_name", Phone: "13800138000"}
	if !application.IsRequiredUsernameChange(legacy) {
		t.Fatal("legacy username should require repair")
	}

	legacy.Name = "ValidUser1"
	if application.IsRequiredUsernameChange(legacy) {
		t.Fatal("a repaired username must not receive another change opportunity")
	}
}

func TestInvalidRequiredUsernameRegexFailsClosed(t *testing.T) {
	application := &Application{EnableSignUp: true, SignupItems: []*SignupItem{{
		Name: "Username", Visible: true, Prompted: true, Regex: "[",
	}}}
	user := &User{Name: "ValidUser1", Phone: "13800138000"}
	if !application.NeedsRequiredAccountSetup(user) {
		t.Fatal("invalid required username regex must block account setup")
	}
}
