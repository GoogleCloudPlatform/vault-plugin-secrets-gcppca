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
	"context"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfig defines the gcppca/config base path on the backend.
func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",

		HelpSynopsis:    "Configure the GCP CA Service secrets engine",
		HelpDescription: "Configure the GCP CA Service secrets engine credentials",

		Fields: map[string]*framework.FieldSchema{
			"credentials": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `
The credentials to use for authenticating to Google Cloud. Leave this blank to
use the Default Application Credentials or instance metadata authentication.
`,
			},

			"scopes": &framework.FieldSchema{
				Type:    framework.TypeCommaStringSlice,
				Default: []string{"https://www.googleapis.com/auth/cloud-platform"},
				Description: `
The list of full-URL scopes to request when authenticating. By default, this
requests https://www.googleapis.com/auth/cloud-platform.
`,
			},
			"pool": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `CaPool to issue a certificate against`,
			},
			"location": &framework.FieldSchema{
				Type: framework.TypeString,
				// AllowedValues is currently not enforced by the framework..
				//AllowedValues: []interface{}{"europe-west1", "us-central1", "us-east1", "us-west1"},
				Description: `Location of the CA Service or`,
			},
			"project": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `GCP ProjectID for the CA Service`,
			},
		},

		ExistenceCheck: b.pathConfigExists,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: withFieldValidator(b.pathConfigWrite),
			logical.ReadOperation:   withFieldValidator(b.pathConfigRead),
			logical.UpdateOperation: withFieldValidator(b.pathConfigWrite),
			logical.DeleteOperation: withFieldValidator(b.pathConfigDelete),
		},
	}
}

// pathConfigExists checks if the configuration exists.
func (b *backend) pathConfigExists(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return false, errwrap.Wrapf("failed to get configuration from storage: {{err}}", err)
	}
	if entry == nil || len(entry.Value) == 0 {
		return false, nil
	}
	return true, nil
}

// pathConfigRead corresponds to READ gcppca/config and is used to
// read the current configuration.
func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	c, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// dont' return credentials, they may show svc account JSON info!
	return &logical.Response{
		Data: map[string]interface{}{
			"project":  c.Project,
			"location": c.Location,
			"pool":     c.Pool,
			"scopes":   c.Scopes,
		},
	}, nil
}

// pathConfigWrite corresponds to both CREATE and UPDATE gcppca/config and is
// used to create or update the current configuration.
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the current configuration, if it exists
	c, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Update the configuration
	changed, err := c.Update(d)
	if err != nil {
		return nil, logical.CodedError(400, err.Error())
	}

	// Only do the following if the config is different
	if changed {
		// Generate a new storage entry
		entry, err := logical.StorageEntryJSON("config", c)
		if err != nil {
			return nil, errwrap.Wrapf("failed to generate JSON configuration: {{err}}", err)
		}

		// Save the storage entry
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, errwrap.Wrapf("failed to persist configuration to storage: {{err}}", err)
		}

		// Invalidate existing client so it reads the new configuration
		b.ResetClient()
	}

	return nil, nil
}

// pathConfigDelete corresponds to DELETE gcppca/config and is used to delete
// all the configuration.
func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "config"); err != nil {
		return nil, errwrap.Wrapf("failed to delete from storage: {{err}}", err)
	}

	// Invalidate existing client so it reads the new configuration
	b.ResetClient()

	return nil, nil
}
