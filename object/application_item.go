// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"fmt"
	"regexp"
	"strings"
)

func (application *Application) GetProviderByCategory(category string) (*Provider, error) {
	providers, err := GetProviders(application.Organization)
	if err != nil {
		return nil, err
	}

	m := map[string]*Provider{}
	for _, provider := range providers {
		if provider.Category != category {
			continue
		}

		m[provider.Name] = provider
	}

	for _, providerItem := range application.Providers {
		if provider, ok := m[providerItem.Name]; ok {
			return provider, nil
		}
	}

	return nil, nil
}

func isProviderItemCountryCodeMatched(providerItem *ProviderItem, countryCode string) bool {
	if len(providerItem.CountryCodes) == 0 {
		return true
	}

	for _, countryCode2 := range providerItem.CountryCodes {
		if countryCode2 == "" || countryCode2 == "All" || countryCode2 == "all" || countryCode2 == countryCode {
			return true
		}
	}
	return false
}

func (application *Application) GetProviderByCategoryAndRule(category string, method string, countryCode string) (*Provider, error) {
	providers, err := GetProviders(application.Organization)
	if err != nil {
		return nil, err
	}

	m := map[string]*Provider{}
	for _, provider := range providers {
		if provider.Category != category {
			continue
		}

		m[provider.Name] = provider
	}

	for _, providerItem := range application.Providers {
		if providerItem.Provider != nil && providerItem.Provider.Category == "SMS" {
			if !isProviderItemCountryCodeMatched(providerItem, countryCode) {
				continue
			}
		}

		if providerItem.Rule == method || providerItem.Rule == "" || providerItem.Rule == "All" || providerItem.Rule == "all" || providerItem.Rule == "None" {
			if provider, ok := m[providerItem.Name]; ok {
				return provider, nil
			}
		}
	}

	return nil, nil
}

func (application *Application) GetEmailProvider(method string) (*Provider, error) {
	return application.GetProviderByCategoryAndRule("Email", method, "All")
}

func (application *Application) GetSmsProvider(method string, countryCode string) (*Provider, error) {
	return application.GetProviderByCategoryAndRule("SMS", method, countryCode)
}

func (application *Application) GetStorageProvider() (*Provider, error) {
	return application.GetProviderByCategory("Storage")
}

func (application *Application) getSignupItem(itemName string) *SignupItem {
	for _, signupItem := range application.SignupItems {
		if signupItem.Name == itemName {
			return signupItem
		}
	}
	return nil
}

func (application *Application) IsSignupItemVisible(itemName string) bool {
	signupItem := application.getSignupItem(itemName)
	if signupItem == nil {
		return false
	}

	return signupItem.Visible
}

func (application *Application) IsSignupItemRequired(itemName string) bool {
	signupItem := application.getSignupItem(itemName)
	if signupItem == nil {
		return false
	}

	return signupItem.Required
}

func (si *SignupItem) isSignupItemPrompted() bool {
	return si.Visible && si.Prompted
}

func (application *Application) GetSignupItemRule(itemName string) string {
	signupItem := application.getSignupItem(itemName)
	if signupItem == nil {
		return ""
	}

	return signupItem.Rule
}

func (application *Application) IsSignupItemValueValid(itemName string, value string) (bool, error) {
	signupItem := application.getSignupItem(itemName)
	if signupItem == nil {
		return false, fmt.Errorf("signup item %q is not configured", itemName)
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return false, nil
	}
	if signupItem.Regex == "" {
		return true, nil
	}

	re, err := regexp.Compile(signupItem.Regex)
	if err != nil {
		return false, fmt.Errorf("invalid signup item regex for %q: %w", itemName, err)
	}
	return re.MatchString(value), nil
}

// IsRequiredUsernameChange reports whether the current account is eligible for
// the one-time legacy username repair. A successful repair makes the username
// match the application rule, so the same account cannot use the flow again.
func (application *Application) IsRequiredUsernameChange(user *User) bool {
	if user == nil {
		return false
	}
	signupItem := application.getSignupItem("Username")
	if signupItem == nil || !signupItem.isSignupItemPrompted() {
		return false
	}

	valid, err := application.IsSignupItemValueValid("Username", user.Name)
	return err != nil || !valid
}

// NeedsRequiredAccountSetup is deliberately narrower than HasPromptPage. It is
// used before an OAuth code is issued so a code cannot be minted with a missing
// verified phone or a legacy username that still requires its one-time repair.
func (application *Application) NeedsRequiredAccountSetup(user *User) bool {
	if application == nil || !application.EnableSignUp || user == nil {
		return false
	}

	phoneItem := application.getSignupItem("Phone")
	if phoneItem != nil && phoneItem.isSignupItemPrompted() && strings.TrimSpace(user.Phone) == "" {
		return true
	}
	return application.IsRequiredUsernameChange(user)
}

func (application *Application) getAllPromptedProviderItems() []*ProviderItem {
	res := []*ProviderItem{}
	for _, providerItem := range application.Providers {
		if providerItem.isProviderPrompted() {
			res = append(res, providerItem)
		}
	}
	return res
}

func (application *Application) getAllPromptedSignupItems() []*SignupItem {
	res := []*SignupItem{}
	for _, signupItem := range application.SignupItems {
		if signupItem.isSignupItemPrompted() {
			res = append(res, signupItem)
		}
	}
	return res
}

func (application *Application) isAffiliationPrompted() bool {
	signupItem := application.getSignupItem("Affiliation")
	if signupItem == nil {
		return false
	}

	return signupItem.Prompted
}

func (application *Application) HasPromptPage() bool {
	providerItems := application.getAllPromptedProviderItems()
	if len(providerItems) != 0 {
		return true
	}

	signupItems := application.getAllPromptedSignupItems()
	if len(signupItems) != 0 {
		return true
	}

	return application.isAffiliationPrompted()
}
