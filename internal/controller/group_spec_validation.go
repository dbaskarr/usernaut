/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"fmt"
	"strings"

	usernautv1alpha1 "github.com/redhat-data-and-ai/usernaut/api/v1alpha1"
	"github.com/redhat-data-and-ai/usernaut/pkg/config"
)

func validate(namespace string, group *usernautv1alpha1.Group, rules config.SpecValidationRulesConfig) error {
	nsRules, ok := rules[namespace]
	if !ok {
		return nil
	}
	return validateGroupName(group, nsRules.Group.GroupName)
}

func validateGroupName(group *usernautv1alpha1.Group, rule config.GroupNameValidationConfig) error {
	if rule.Prefix != "" && !strings.HasPrefix(group.Spec.GroupName, rule.Prefix) {
		return fmt.Errorf("spec.group_name must start with %q", rule.Prefix)
	}

	return nil
}
