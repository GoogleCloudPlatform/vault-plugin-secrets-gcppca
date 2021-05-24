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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/option"
	"google.golang.org/grpc/connectivity"

	pcaapi "cloud.google.com/go/security/privateca/apiv1"
	hclog "github.com/hashicorp/go-hclog"
)

// testBackend creates a new isolated instance of the backend for testing.
func testBackend(tb testing.TB) (*backend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}
	return b.(*backend), config.StorageView
}

// testFieldValidation verifies the given path has field validation.
func testFieldValidation(tb testing.TB, op logical.Operation, pth string) {
	tb.Helper()

	b, storage := testBackend(tb)
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: op,
		Path:      pth,
		Data: map[string]interface{}{
			"literally-never-a-key": true,
		},
	})
	if err == nil {
		tb.Error("expected error")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		tb.Error(err)
	}
}

// testPCAClient creates a new Certificate Service client with the default scopes and user
// agent.
func testPCAClient(tb testing.TB) *pcaapi.CertificateAuthorityClient {
	tb.Helper()

	ctx := context.Background()
	kmsClient, err := pcaapi.NewCertificateAuthorityClient(ctx,
		option.WithScopes(defaultScope),
		option.WithUserAgent(useragent.String()),
	)
	if err != nil {
		tb.Fatalf("failed to create kms client: %s", err)
	}

	return kmsClient
}

func TestBackend_PCAClient(t *testing.T) {
	t.Parallel()

	t.Run("allows_concurrent_reads", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		_, closer1, err := b.PCAClient(storage)
		if err != nil {
			t.Fatal(err)
		}
		defer closer1()

		doneCh := make(chan struct{})
		go func() {
			_, closer2, err := b.PCAClient(storage)
			if err != nil {
				t.Fatal(err)
			}
			defer closer2()
			close(doneCh)
		}()

		select {
		case <-doneCh:
		case <-time.After(1 * time.Second):
			t.Errorf("client was not available")
		}
	})

	t.Run("caches", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		client1, closer1, err := b.PCAClient(storage)
		if err != nil {
			t.Fatal(err)
		}
		defer closer1()

		client2, closer2, err := b.PCAClient(storage)
		if err != nil {
			t.Fatal(err)
		}
		defer closer2()

		// Note: not a bug; literally checking object equality
		if client1 != client2 {
			t.Errorf("expected %#v to be %#v", client1, client2)
		}
	})

	t.Run("expires", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)
		b.pcaClientLifetime = 50 * time.Millisecond

		client1, closer1, err := b.PCAClient(storage)
		if err != nil {
			t.Fatal(err)
		}
		closer1()

		time.Sleep(100 * time.Millisecond)

		client2, closer2, err := b.PCAClient(storage)
		if err != nil {
			t.Fatal(err)
		}
		closer2()

		if client1 == client2 {
			t.Errorf("expected %#v to not be %#v", client1, client2)
		}
	})
}

func TestBackend_ResetClient(t *testing.T) {
	t.Parallel()

	t.Run("closes_client", func(t *testing.T) {
		t.Parallel()

		b, storage := testBackend(t)

		client, closer, err := b.PCAClient(storage)
		if err != nil {
			t.Fatal(err)
		}

		// Verify the client is "open"
		if client.Connection().GetState() == connectivity.Shutdown {
			t.Fatalf("connection is already stopped")
		}

		// Stop read lock
		closer()

		// Reset the clients
		b.ResetClient()

		// Verify the client closed
		if state := client.Connection().GetState(); state != connectivity.Shutdown {
			t.Errorf("expected client to be closed, was: %v", state)
		}
	})
}

func TestBackend_Config(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		c    []byte
		e    *Config
		err  bool
	}{
		{
			"default",
			nil,
			DefaultConfig(),
			false,
		},
		{
			"saved",
			[]byte(`{"credentials":"foo", "scopes":["bar"]}`),
			&Config{
				Credentials: "foo",
				Scopes:      []string{"bar"},
			},
			false,
		},
		{
			"invalid",
			[]byte(`{x`),
			nil,
			true,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, storage := testBackend(t)

			if tc.c != nil {
				if err := storage.Put(context.Background(), &logical.StorageEntry{
					Key:   "config",
					Value: tc.c,
				}); err != nil {
					t.Fatal(err)
				}
			}

			c, err := b.Config(context.Background(), storage)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(c, tc.e) {
				t.Errorf("expected %#v to be %#v", c, tc.e)
			}
		})
	}
}
