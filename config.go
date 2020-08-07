// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcppca

import (
	"errors"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/strutil"
)

const (
	defaultScope = "https://www.googleapis.com/auth/cloud-platform"
)

// ref: https://github.com/hashicorp/vault-plugin-secrets-gcpkms/blob/master/config.go

// Config is the stored configuration.
type Config struct {
	Credentials string   `json:"credentials"`
	Scopes      []string `json:"scopes"`
	Issuer      string   `json:"issuer"`
	Location    string   `json:"location"`
	Project     string   `json:"project"`
}

// DefaultConfig returns a config with the default values.
func DefaultConfig() *Config {
	return &Config{
		Scopes: []string{defaultScope},
	}
}

// Update updates the configuration from the given field data.
func (c *Config) Update(d *framework.FieldData) (bool, error) {
	if d == nil {
		return false, nil
	}

	changed := false

	if v, ok := d.GetOk("credentials"); ok {
		nv := strings.TrimSpace(v.(string))
		if nv != c.Credentials {
			c.Credentials = nv
			changed = true
		}
	}

	if v, ok := d.GetOk("scopes"); ok {
		nv := strutil.RemoveDuplicates(v.([]string), true)
		if !strutil.EquivalentSlices(nv, c.Scopes) {
			c.Scopes = nv
			changed = true
		}
	}

	if v, ok := d.GetOk("issuer"); ok {
		nv := strings.TrimSpace(v.(string))
		if nv != c.Issuer {
			c.Issuer = nv
			changed = true
		}
	}

	if v, ok := d.GetOk("location"); ok {
		nv := strings.TrimSpace(v.(string))
		if nv != c.Location {
			c.Location = nv
			changed = true
		}
	}

	if v, ok := d.GetOk("project"); ok {
		nv := strings.TrimSpace(v.(string))
		if nv != c.Project {
			c.Project = nv
			changed = true
		}
	}

	if c.Issuer == "" || c.Location == "" || c.Project == "" {
		return true, errors.New("Must specify Issuer, Location and Project in config ")
	}

	return changed, nil
}
