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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
)

func (b *backend) pathCSR() *framework.Path {
	return &framework.Path{
		Pattern: "issue-with-csr/" + framework.GenericNameRegex("name"),

		HelpSynopsis:    "Provide CSR to Vault",
		HelpDescription: `Provide Vault with CSR; sign it using Private CA`,

		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Certificate Name value`,
			},
			"labels": &framework.FieldSchema{
				Type:        framework.TypeMap,
				Description: `Lables for the certificate`,
			},
			"pem_csr": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `CSR PEM contents`,
			},
			"validity": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The validity of this certificate, as an ISO8601 duration. Defaults to	30 days. (P30D)`,
				Default: "P30D",
			},
			"issuing_certificate_authority": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Optional. The resource ID of the CertificateAuthority that should issue the certificate. `,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: withFieldValidator(b.pathCSRWrite),
			logical.UpdateOperation: withFieldValidator(b.pathCSRWrite),
			logical.DeleteOperation: withFieldValidator(b.pathCSRDelete),
		},
	}
}

func (b *backend) pathCSRWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var name string
	var csrPEM string
	var labels map[string]string
	var issuingCertificateAuthority string

	name = d.Get("name").(string)
	if v, ok := d.GetOk("labels"); ok {
		labels = v.(map[string]string)
	}

	var validity time.Duration
	if v, ok := d.GetOk("validity"); ok {
		var err error
		validity, err = parseDuration(v.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Unable to parse validity period %s %v", v.(string), err)), logical.ErrInvalidRequest
		}
	}

	if v, ok := d.GetOk("pem_csr"); ok {
		csrPEM = v.(string)
	} else {
		return logical.ErrorResponse("PEM contents cannot be empty"), logical.ErrInvalidRequest
	}

	if v, ok := d.GetOk("issuing_certificate_authority"); ok {
		issuingCertificateAuthority = v.(string)
	}

	// Check if this is a valid PEM formatted CSR
	block, _ := pem.Decode([]byte(csrPEM))
	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Unable to parse CSR %v", err)), logical.ErrInvalidRequest
	} else {
		b.Logger().Debug("Parsed CSR with Subject: %v", csrParsed.Subject)
	}

	// First read the configuration settings that define the specifications of the CA
	cfg, err := b.Config(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	pool := cfg.Pool
	projectID := cfg.Project
	location := cfg.Location

	pcaClient, closer, err := b.PCAClient(req.Storage)
	if err != nil {
		return nil, err
	}
	defer closer()

	parent := fmt.Sprintf("projects/%s/locations/%s/caPools/%s", projectID, location, pool)

	var creq privatecapb.CreateCertificateRequest
	creq = privatecapb.CreateCertificateRequest{
		Parent:        parent,
		CertificateId: name,
		Certificate: &privatecapb.Certificate{
			Labels:   labels,
			Lifetime: ptypes.DurationProto(validity),
			CertificateConfig: &privatecapb.Certificate_PemCsr{
				PemCsr: string(csrPEM),
			},
		},
		IssuingCertificateAuthorityId: issuingCertificateAuthority,
	}

	cresp, err := pcaClient.CreateCertificate(ctx, &creq)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"pubcert": cresp.GetPemCertificate(),
		},
	}, nil
}

func (b *backend) pathCSRDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var name string
	name = d.Get("name").(string)
	cfg, err := b.Config(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	pool := cfg.Pool
	projectID := cfg.Project
	location := cfg.Location

	if pool == "" || projectID == "" || location == "" {
		return logical.ErrorResponse("Configuration settings not found: Pool, ProjectID and Location must be set in <mount>/config"), logical.ErrInvalidRequest
	}

	pcaClient, closer, err := b.PCAClient(req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	defer closer()

	b.Logger().Debug("Attempting to see if this cert exists %v", pool, name)

	parent := fmt.Sprintf("projects/%s/locations/%s/caPools/%s/certificates/%s", projectID, location, pool, name)
	getReq := &privatecapb.GetCertificateRequest{
		Name: parent,
	}
	gcert, err := pcaClient.GetCertificate(ctx, getReq)
	if err != nil {
		b.Logger().Debug("CertificateName doesn't exist..this maybe an anonymous cert exiting [", pool, "]  certspec: ", name)
		// not sure what to return here, err or nil
		//return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		return &logical.Response{}, nil
	}

	if gcert.RevocationDetails != nil {
		b.Logger().Debug("Certificate already Revoked [", name+"]  certspec: ", gcert.RevocationDetails.RevocationState.String)
		// not sure what to return here, err or nil
		//return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		return &logical.Response{}, nil
	}

	b.Logger().Debug("Revoking Certificate %s", parent)
	crev := &privatecapb.RevokeCertificateRequest{
		Name:   parent,
		Reason: privatecapb.RevocationReason_CESSATION_OF_OPERATION,
	}
	crevresp, err := pcaClient.RevokeCertificate(ctx, crev)
	if err != nil {
		return logical.ErrorResponse("Error revoking certificate"), logical.ErrInvalidRequest
	}

	b.Logger().Debug("Certificate Revoked %s", crevresp.Name)

	return &logical.Response{}, nil
}
