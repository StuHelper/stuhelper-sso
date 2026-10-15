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
	"reflect"
	"testing"
)

func TestReplaceAttributeValueSupportsBooleanUserFields(t *testing.T) {
	user := &User{
		IsAdmin:     true,
		IsForbidden: false,
		IsDeleted:   true,
	}

	got := replaceAttributeValue(
		user,
		"admin=$user.isAdmin forbidden=$user.isForbidden deleted=$user.isDeleted",
	)
	want := []string{"admin=true forbidden=false deleted=true"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("replaceAttributeValue() = %#v, want %#v", got, want)
	}
}

func TestCustomClaimsCanOverrideBooleanFieldsWithStrings(t *testing.T) {
	claims := Claims{
		User: &User{
			IsAdmin:     true,
			IsForbidden: false,
			IsDeleted:   false,
		},
	}
	tokenFields := []string{"IsAdmin", "IsForbidden", "IsDeleted"}
	tokenAttributes := []*JwtItem{
		{
			Name:     "isAdmin",
			Category: "Static Value",
			Value:    "$user.isAdmin",
			Type:     "String",
		},
		{
			Name:     "isForbidden",
			Category: "Static Value",
			Value:    "$user.isForbidden",
			Type:     "String",
		},
		{
			Name:     "isDeleted",
			Category: "Static Value",
			Value:    "$user.isDeleted",
			Type:     "String",
		},
	}

	got := getClaimsCustom(claims, tokenFields, tokenAttributes)
	want := map[string]string{
		"isAdmin":     "true",
		"isForbidden": "false",
		"isDeleted":   "false",
	}
	for claimName, wantValue := range want {
		if gotValue, ok := got[claimName].(string); !ok || gotValue != wantValue {
			t.Errorf("claim %q = %#v, want string %q", claimName, got[claimName], wantValue)
		}
	}
}
