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

package routers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationObjectFromIDUsesOrganizationNameForOrganizationUpdates(t *testing.T) {
	owner, name, err := authorizationObjectFromID("/api/update-organization", "admin/stuhelper")
	require.NoError(t, err)
	assert.Equal(t, "stuhelper", owner)
	assert.Equal(t, "stuhelper", name)
}

func TestAuthorizationObjectFromIDPreservesOwnerForOtherResources(t *testing.T) {
	owner, name, err := authorizationObjectFromID("/api/update-application", "admin/app-stuhelper")
	require.NoError(t, err)
	assert.Equal(t, "admin", owner)
	assert.Equal(t, "app-stuhelper", name)
}
