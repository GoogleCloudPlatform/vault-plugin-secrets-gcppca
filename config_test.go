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
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
)

func TestConfig_Update(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		new     *Config
		d       *framework.FieldData
		r       *Config
		changed bool
		err     bool
	}{
		{
			"empty",
			&Config{},
			nil,
			&Config{},
			false,
			false,
		},
		{
			"expect_project",
			&Config{
				Credentials: "creds",
				Issuer:      "iss",
				Location:    "us-central1",
			},
			&framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": "creds",
					"issuer":      "iss",
					"location":    "us-central1",
				},
			},
			&Config{
				Credentials: "creds",
				Issuer:      "iss",
				Location:    "us-central1",
			},
			true,
			true,
		},
		{
			"expect_issuer",
			&Config{
				Credentials: "creds",
				Project:     "project",
				Location:    "us-central1",
			},
			&framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": "creds",
					"project":     "project",
					"location":    "us-central1",
				},
			},
			&Config{
				Credentials: "creds",
				Project:     "project",
				Location:    "us-central1",
			},
			true,
			true,
		},
		{
			"expect_location",
			&Config{
				Credentials: "creds",
				Project:     "project",
				Issuer:      "iss",
			},
			&framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": "creds",
					"issuer":      "iss",
					"project":     "project",
				},
			},
			&Config{
				Credentials: "creds",
				Project:     "project",
				Issuer:      "iss",
			},
			true,
			true,
		},
		{
			"keeps_existing",
			&Config{
				Credentials: "creds",
				Project:     "project",
				Issuer:      "iss",
				Location:    "us-central1",
			},
			nil,
			&Config{
				Credentials: "creds",
				Project:     "project",
				Issuer:      "iss",
				Location:    "us-central1",
			},
			false,
			false,
		},
		{
			"overwrites_changes",
			&Config{
				Credentials: "creds",
				Project:     "project",
				Issuer:      "iss",
				Location:    "us-central1",
			},
			&framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": "foo",
					"project":     "project",
					"issuer":      "iss",
					"location":    "us-central1",
				},
			},
			&Config{
				Credentials: "foo",
				Project:     "project",
				Issuer:      "iss",
				Location:    "us-central1",
			},
			true,
			false,
		},
		{
			"overwrites_and_new",
			&Config{
				Credentials: "creds",
				Project:     "project",
				Issuer:      "iss",
				Location:    "us-central1",
			},
			&framework.FieldData{
				Raw: map[string]interface{}{
					"credentials": "foo",
					"scopes":      "bar",
					"project":     "project",
					"issuer":      "iss",
					"location":    "us-central1",
				},
			},
			&Config{
				Credentials: "foo",
				Scopes:      []string{"bar"},
				Project:     "project",
				Issuer:      "iss",
				Location:    "us-central1",
			},
			true,
			false,
		},
		{
			"no_changes_order",
			&Config{
				Scopes:   []string{"bar", "foo"},
				Project:  "project",
				Issuer:   "iss",
				Location: "us-central1",
			},
			&framework.FieldData{
				Raw: map[string]interface{}{
					"scopes":   "foo,bar",
					"project":  "project",
					"issuer":   "iss",
					"location": "us-central1",
				},
			},
			&Config{
				Scopes:   []string{"bar", "foo"},
				Project:  "project",
				Issuer:   "iss",
				Location: "us-central1",
			},
			false,
			false,
		},
		{
			"no_changes_caps",
			&Config{
				Scopes:   []string{"bar", "foo"},
				Project:  "project",
				Issuer:   "iss",
				Location: "us-central1",
			},
			&framework.FieldData{
				Raw: map[string]interface{}{
					"scopes":   "FOO,baR",
					"project":  "project",
					"issuer":   "iss",
					"location": "us-central1",
				},
			},
			&Config{
				Scopes:   []string{"bar", "foo"},
				Project:  "project",
				Issuer:   "iss",
				Location: "us-central1",
			},
			false,
			false,
		},
		{
			"no_changes_dupes",
			&Config{
				Scopes:   []string{"bar", "foo"},
				Project:  "project",
				Issuer:   "iss",
				Location: "us-central1",
			},
			&framework.FieldData{
				Raw: map[string]interface{}{
					"scopes":   "foo, foo, foo, bar",
					"project":  "project",
					"issuer":   "iss",
					"location": "us-central1",
				},
			},
			&Config{
				Scopes:   []string{"bar", "foo"},
				Project:  "project",
				Issuer:   "iss",
				Location: "us-central1",
			},
			false,
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.d != nil {
				var b backend
				tc.d.Schema = b.pathConfig().Fields
			}

			changed, err := tc.new.Update(tc.d)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if changed != tc.changed {
				t.Errorf("expected %t to be %t", changed, tc.changed)
			}

			if v, exp := tc.new.Scopes, tc.r.Scopes; !reflect.DeepEqual(v, exp) {
				t.Errorf("expected %q to be %q", v, exp)
			}

			if v, exp := tc.new.Credentials, tc.r.Credentials; v != exp {
				t.Errorf("expected %q to be %q", v, exp)
			}
		})
	}
}
