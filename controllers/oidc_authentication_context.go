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
	"strconv"
	"strings"

	"github.com/casdoor/casdoor/object"
)

const (
	oidcSessionAMRKey      = "oidcAuthenticationMethods"
	oidcSessionAuthTimeKey = "oidcAuthenticationTime"
	oidcSessionACRKey      = "oidcAuthenticationContext"
)

func (c *ApiController) setOIDCAuthenticationContext(authentication *object.AuthenticationContext) {
	if authentication == nil {
		c.DelSession(oidcSessionAMRKey)
		c.DelSession(oidcSessionAuthTimeKey)
		c.DelSession(oidcSessionACRKey)
		return
	}
	c.SetSession(oidcSessionAMRKey, strings.Join(authentication.AMR, " "))
	c.SetSession(oidcSessionAuthTimeKey, strconv.FormatInt(authentication.AuthTime, 10))
	c.SetSession(oidcSessionACRKey, authentication.ACR)
}

func (c *ApiController) getOIDCAuthenticationContext() *object.AuthenticationContext {
	amrValue, ok := c.GetSession(oidcSessionAMRKey).(string)
	if !ok {
		return nil
	}
	authTimeValue, ok := c.GetSession(oidcSessionAuthTimeKey).(string)
	if !ok {
		return nil
	}
	authTime, err := strconv.ParseInt(authTimeValue, 10, 64)
	if err != nil {
		return nil
	}
	acr, ok := c.GetSession(oidcSessionACRKey).(string)
	if !ok {
		return nil
	}
	return object.RestoreAuthenticationContext(strings.Fields(amrValue), authTime, acr)
}
