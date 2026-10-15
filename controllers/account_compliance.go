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

import (
	"encoding/json"
	"strings"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

type requiredUsernameUpdateForm struct {
	ApplicationOwner string `json:"applicationOwner"`
	ApplicationName  string `json:"applicationName"`
	Username         string `json:"username"`
}

// UpdateRequiredUsername gives a legacy account exactly one repair path: the
// endpoint is available only while its current username fails the prompted
// application's signup regex. After a successful rename the same predicate is
// false, while the ordinary account page continues to treat Name as admin-only.
func (c *ApiController) UpdateRequiredUsername() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	var input requiredUsernameUpdateForm
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &input); err != nil {
		c.ResponseError(err.Error())
		return
	}
	input.ApplicationOwner = strings.TrimSpace(input.ApplicationOwner)
	input.ApplicationName = strings.TrimSpace(input.ApplicationName)
	input.Username = strings.TrimSpace(input.Username)
	if util.IsStringsEmpty(input.ApplicationOwner, input.ApplicationName, input.Username) {
		c.ResponseError(c.T("general:Missing parameter"))
		return
	}

	application, err := object.GetApplication(util.GetId(input.ApplicationOwner, input.ApplicationName))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if application == nil || application.Organization != user.Owner {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}
	if !application.IsRequiredUsernameChange(user) {
		c.ResponseError("This account no longer has a one-time username change available")
		return
	}

	valid, err := application.IsSignupItemValueValid("Username", input.Username)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if !valid {
		c.ResponseError("The new username does not match the registration rule")
		return
	}

	updatedUser := *user
	updatedUser.Name = input.Username
	if msg := object.CheckUpdateUser(user, &updatedUser, c.GetAcceptLanguage()); msg != "" {
		c.ResponseError(msg)
		return
	}

	updated, err := object.UpdateUser(user.GetId(), &updatedUser, []string{"name"}, false)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if !updated {
		c.ResponseError("The username was not updated")
		return
	}

	c.SetSessionUsername(updatedUser.GetId())
	c.ResponseOk(updatedUser.GetId())
}
