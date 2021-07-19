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
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	pcaapi "cloud.google.com/go/security/privateca/apiv1"
)

var (
	defaultClientLifetime = 30 * time.Minute
)

// ref: https://github.com/hashicorp/vault-plugin-secrets-gcpkms/blob/master/backend.go

type backend struct {
	*framework.Backend

	// pcaClient is the actual client for connecting to PrivateCA. It is cached on
	// the backend for efficiency.
	pcaClient           *pcaapi.CertificateAuthorityClient
	pcaClientCreateTime time.Time
	pcaClientLifetime   time.Duration
	pcaClientLock       sync.RWMutex

	// ctx and ctxCancel are used to control overall plugin shutdown. These
	// contexts are given to any client libraries or requests that should be
	// terminated during plugin termination.
	ctx       context.Context
	ctxCancel context.CancelFunc
	ctxLock   sync.Mutex
}

// Factory returns a configured instance of the backend.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend returns a configured instance of the backend.
func Backend() *backend {
	var b backend

	b.pcaClientLifetime = defaultClientLifetime
	b.ctx, b.ctxCancel = context.WithCancel(context.Background())

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help: "The GCP CA secrets engine provides issuing and revoking GCP CA based " +
			"certificates.",

		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathGenerateKey(),
			b.pathCSR(),
		},

		Invalidate: b.invalidate,
		Clean:      b.clean,
	}

	return &b
}

// clean cancels the shared contexts. This is called just before unmounting
// the plugin.
func (b *backend) clean(_ context.Context) {
	b.ctxLock.Lock()
	b.ctxCancel()
	b.ctxLock.Unlock()
}

// invalidate resets the plugin. This is called when a key is updated via
// replication.
func (b *backend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.ResetClient()
	}
}

// ResetClient closes any connected clients.
func (b *backend) ResetClient() {
	b.pcaClientLock.Lock()
	b.resetClient()
	b.pcaClientLock.Unlock()
}

// resetClient rests the underlying client. The caller is responsible for
// acquiring and releasing locks. This method is not safe to call concurrently.
func (b *backend) resetClient() {
	if b.pcaClient != nil {
		b.pcaClient.Close()
		b.pcaClient = nil
	}

	b.pcaClientCreateTime = time.Unix(0, 0).UTC()
}

// PrivateCA creates a new client for talking to the GCP PrivateCA service.
func (b *backend) PCAClient(s logical.Storage) (*pcaapi.CertificateAuthorityClient, func(), error) {
	// If the client already exists and is valid, return it
	b.pcaClientLock.RLock()
	if b.pcaClient != nil && time.Now().UTC().Sub(b.pcaClientCreateTime) < b.pcaClientLifetime {
		closer := func() { b.pcaClientLock.RUnlock() }
		return b.pcaClient, closer, nil
	}
	b.pcaClientLock.RUnlock()

	// Acquire a full lock. Since all invocations acquire a read lock and defer
	// the release of that lock, this will block until all clients are no longer
	// in use. At that point, we can acquire a globally exclusive lock to close
	// any connections and create a new client.
	b.pcaClientLock.Lock()

	b.Logger().Debug("Creating new PrivateCA client")

	// Attempt to close an existing client if we have one.
	b.resetClient()

	// Get the config
	config, err := b.Config(b.ctx, s)
	if err != nil {
		b.pcaClientLock.Unlock()
		return nil, nil, err
	}

	// If credentials were provided, use those. Otherwise fall back to the
	// default application credentials.
	var creds *google.Credentials
	if config.Credentials != "" {
		creds, err = google.CredentialsFromJSON(b.ctx, []byte(config.Credentials), config.Scopes...)
		if err != nil {
			b.pcaClientLock.Unlock()
			return nil, nil, errwrap.Wrapf("failed to parse credentials: {{err}}", err)
		}
	} else {
		creds, err = google.FindDefaultCredentials(b.ctx, config.Scopes...)
		if err != nil {
			b.pcaClientLock.Unlock()
			return nil, nil, errwrap.Wrapf("failed to get default token source: {{err}}", err)
		}
	}

	// Create and return the GCP CA client with a custom user agent.
	client, err := pcaapi.NewCertificateAuthorityClient(b.ctx,
		option.WithCredentials(creds),
		option.WithScopes(config.Scopes...),
		option.WithUserAgent(useragent.String()),
	)
	if err != nil {
		b.pcaClientLock.Unlock()
		return nil, nil, errwrap.Wrapf("failed to create PrivateCA client: {{err}}", err)
	}

	// Cache the client
	b.pcaClient = client
	b.pcaClientCreateTime = time.Now().UTC()
	b.pcaClientLock.Unlock()

	b.pcaClientLock.RLock()
	closer := func() { b.pcaClientLock.RUnlock() }
	return client, closer, nil
}

// Config parses and returns the configuration data from the storage backend.
// Even when no user-defined data exists in storage, a Config is returned with
// the default values.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*Config, error) {
	c := DefaultConfig()

	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, errwrap.Wrapf("failed to get configuration from storage: {{err}}", err)
	}
	if entry == nil || len(entry.Value) == 0 {
		return c, nil
	}

	if err := entry.DecodeJSON(&c); err != nil {
		return nil, errwrap.Wrapf("failed to decode configuration: {{err}}", err)
	}
	return c, nil
}
