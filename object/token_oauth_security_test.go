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
	"errors"
	"testing"
	"time"
)

func TestValidateSubjectTokenAudience(t *testing.T) {
	if err := validateSubjectTokenAudience("issuer", "issuer", nil); err != nil {
		t.Fatalf("issuing client should be allowed to exchange its own token: %#v", err)
	}
	if err := validateSubjectTokenAudience("issuer", "requester", []string{"requester"}); err != nil {
		t.Fatalf("explicit audience should be allowed: %#v", err)
	}
	if err := validateSubjectTokenAudience("issuer", "requester", []string{"other"}); err == nil || err.Error != InvalidGrant {
		t.Fatalf("missing audience should fail with invalid_grant: %#v", err)
	}
}

func TestValidateStoredSubjectToken(t *testing.T) {
	now := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	application := &Application{Owner: "admin", Name: "issuer"}
	active := &Token{
		Owner:        "admin",
		Application:  "issuer",
		Organization: "example",
		User:         "alice",
		CreatedTime:  now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresIn:    3600,
	}

	tests := []struct {
		name      string
		lookup    subjectTokenLookup
		wantError bool
		wantGrant bool
	}{
		{
			name: "active",
			lookup: func(string) (*Token, error) {
				copy := *active
				return &copy, nil
			},
		},
		{
			name: "lookup failure",
			lookup: func(string) (*Token, error) {
				return nil, errors.New("database unavailable")
			},
			wantError: true,
		},
		{
			name: "missing",
			lookup: func(string) (*Token, error) {
				return nil, nil
			},
			wantGrant: true,
		},
		{
			name: "revoked",
			lookup: func(string) (*Token, error) {
				copy := *active
				copy.ExpiresIn = 0
				return &copy, nil
			},
			wantGrant: true,
		},
		{
			name: "expired",
			lookup: func(string) (*Token, error) {
				copy := *active
				copy.CreatedTime = now.Add(-2 * time.Hour).Format(time.RFC3339)
				return &copy, nil
			},
			wantGrant: true,
		},
		{
			name: "record mismatch",
			lookup: func(string) (*Token, error) {
				copy := *active
				copy.User = "mallory"
				return &copy, nil
			},
			wantGrant: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tokenErr, err := validateStoredSubjectToken("subject-token", application, "example", "alice", test.lookup, now)
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected lookup error: %v", err)
			}
			if (tokenErr != nil) != test.wantGrant {
				t.Fatalf("unexpected token error: %#v", tokenErr)
			}
			if tokenErr != nil && tokenErr.Error != InvalidGrant {
				t.Fatalf("expected invalid_grant, got %#v", tokenErr)
			}
		})
	}
}
