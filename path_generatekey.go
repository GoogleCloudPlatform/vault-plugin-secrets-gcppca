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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/iterator"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
)

const (

	// key_usage
	digital_signature  = "digital_signature"
	content_commitment = "content_commitment"
	key_encipherment   = "key_encipherment"
	data_encipherment  = "data_encipherment"
	key_agreement      = "key_agreement"
	cert_sign          = "cert_sign"
	crl_sign           = "crl_sign"
	encipher_only      = "encipher_only"
	decipher_only      = "decipher_only"

	// key_types
	key_type_rsa   = "rsa"
	key_type_ecdsa = "ecdsa"

	// extended_key_usage
	server_auth      = "server_auth"
	client_auth      = "client_auth"
	code_signing     = "code_signing"
	email_protection = "email_protection"
	time_stamping    = "time_stamping"
	ocsp_signing     = "ocsp_signing"
)

var (
	valid_key_types  = []string{key_type_rsa, key_type_ecdsa}
	valid_key_usages = []string{digital_signature, content_commitment, key_encipherment, data_encipherment,
		key_agreement, cert_sign, crl_sign, encipher_only, decipher_only}
	valid_extended_key_usages = []string{server_auth, client_auth, code_signing, email_protection,
		time_stamping, ocsp_signing}
	valid_reusable_config = []string{} // derived from api
)

func (b *backend) pathGenerateKey() *framework.Path {
	return &framework.Path{
		Pattern: "issue-with-genkey/" + framework.GenericNameRegex("name"),

		HelpSynopsis:    "Generate CSR on Vault",
		HelpDescription: `Generate CSR on Vault; sign it using Private CA`,

		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Certificate Name`,
			},
			"labels": &framework.FieldSchema{
				Type:        framework.TypeMap,
				Description: `Lables for the certificate`,
			},
			"key_type": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Generate RSA or ECDSA key`,
				Default:     "rsa",
			},
			"dns_san": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `DNS SAN values`,
			},
			"email_san": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `Email SAN values`,
			},
			"ip_san": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `IP SAN values`,
			},
			"uri_san": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `URI SAN values`,
			},
			"subject": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: `Subject (C=US,ST=California,L=Mountain View,O=Google LLC,CN=google.com)`,
			},
			"key_usages": &framework.FieldSchema{
				Type: framework.TypeCommaStringSlice,
				Description: `One of:  digital_signature, content_commitment, key_encipherment,
				data_encipherment, key_agreement, cert_sign, crl_sign,
				encipher_only, decipher_only.`,
			},
			"extended_key_usages": &framework.FieldSchema{
				Type: framework.TypeCommaStringSlice,
				Description: `One of:  server_auth, client_auth,
				code_signing, email_protection, time_stamping, ocsp_signing`,
			},
			"reusable_config": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Reusable Config Name`,
			},
			"max_chain_length": &framework.FieldSchema{
				Type: framework.TypeInt,
				Description: `Maximum depth of subordinate CAs allowed under this CA for a CA
				certificate.`,
			},
			"is_ca_cert": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: `is-ca-cert`,
			},
			"validity": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The validity of this certificate, as an ISO8601 duration. Defaults to	30 days. (P30D)`,
				Default: "P30D",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: withFieldValidator(b.pathGenerateKeyWrite),
			logical.UpdateOperation: withFieldValidator(b.pathGenerateKeyWrite),
			logical.DeleteOperation: withFieldValidator(b.pathGenerateKeyDelete),
		},
	}
}

func (b *backend) pathGenerateKeyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var name string

	var dnsSAN []string
	var key_type string
	var emailSAN []string
	var ipSAN []string
	var uriSAN []string
	var key_usages []string
	var extended_key_usages []string
	var reusable_config string
	var validity time.Duration
	var labels map[string]string
	var is_ca_cert bool

	name = d.Get("name").(string)

	b.Logger().Debug(fmt.Sprintf("Start generatecert for %s", name))

	// First read the configuration settings that define the specifications of the CA
	cfg, err := b.Config(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	issuer := cfg.Issuer
	projectID := cfg.Project
	location := cfg.Location

	if issuer == "" || projectID == "" || location == "" {
		return logical.ErrorResponse("Configuration settings not found: Issuer, ProjectID and Location must be set in <mount>/config"), logical.ErrInvalidRequest
	}

	pcaClient, closer, err := b.PCAClient(req.Storage)
	if err != nil {
		return nil, err
	}
	defer closer()

	if v, ok := d.GetOk("dns_san"); ok {
		dnsSAN = v.([]string)
	}

	if v, ok := d.GetOk("key_type"); ok {
		if !contains(valid_key_types, v.(string)) {
			return logical.ErrorResponse("key_type must be either rsa or ecdsa"), logical.ErrInvalidRequest
		}

	}
	key_type = d.Get("key_type").(string)

	if v, ok := d.GetOk("labels"); ok {
		labels = v.(map[string]string)
	}

	if v, ok := d.GetOk("email_san"); ok {
		emailSAN = v.([]string)
	}

	if v, ok := d.GetOk("ip_san"); ok {
		ipSAN = v.([]string)
	}

	if v, ok := d.GetOk("uri_san"); ok {
		uriSAN = v.([]string)
	}

	subjectValues := make(map[string]string)
	if v, ok := d.GetOk("subject"); ok {
		subjstr := v.([]string)
		for _, match := range subjstr {
			val := strings.Split(match, "=")
			if len(val) != 2 {
				return logical.ErrorResponse("Invalid Subject field in Request"), logical.ErrInvalidRequest
			}
			switch strings.ToUpper(val[0]) {
			case "C":
				subjectValues["country"] = strings.TrimSpace(val[1])
			case "O":
				subjectValues["organization"] = strings.TrimSpace(val[1])
			case "OU":
				subjectValues["organizationunit"] = strings.TrimSpace(val[1])
			case "L":
				subjectValues["locality"] = strings.TrimSpace(val[1])
			case "ST":
				subjectValues["province"] = strings.TrimSpace(val[1])
			case "CN":
				subjectValues["cn"] = strings.TrimSpace(val[1])
			}
		}
	}

	valid_reusable_config, err := b.getReusableConfigs(ctx, pcaClient, location)
	if err != nil {
		return logical.ErrorResponse("Could not recall reusable configs from CA Service "), logical.ErrInvalidRequest
	}

	if v, ok := d.GetOk("reusable_config"); ok {
		if !contains(valid_reusable_config, v.(string)) {
			return logical.ErrorResponse("Invalid reusable configs, must one of ", valid_reusable_config), logical.ErrInvalidRequest
		}
		reusable_config = v.(string)
	}

	if v, ok := d.GetOk("key_usages"); ok {
		for _, usage := range v.([]string) {
			if !contains(valid_key_usages, usage) {
				return logical.ErrorResponse("Invalid key_usages, must one of ", valid_key_usages), logical.ErrInvalidRequest
			}
		}
		key_usages = v.([]string)
	}

	if v, ok := d.GetOk("extended_key_usages"); ok {
		for _, usage := range v.([]string) {
			if !contains(valid_extended_key_usages, usage) {
				return logical.ErrorResponse("Invalid extended_key_usages, must one of ", valid_extended_key_usages), logical.ErrInvalidRequest
			}
		}
		extended_key_usages = v.([]string)
	}

	if len(reusable_config) > 0 && (len(key_usages) > 0 || len(extended_key_usages) > 0) {
		b.Logger().Error("Either reusable config or (key_usages|extended_key_usage) must be specified")
		return logical.ErrorResponse("Either reusable config or (key_usages|extended_key_usage) must be specified"), logical.ErrInvalidRequest
	}

	if v, ok := d.GetOk("is_ca_cert"); ok {
		is_ca_cert = v.(bool)
	}

	if v, ok := d.GetOk("validity"); ok {
		var err error
		validity, err = parseDuration(v.(string))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Unable to parse validity period %s %v", v.(string), err)), logical.ErrInvalidRequest
		}
	}

	var pubkey *privatecapb.PublicKey
	var publicKeyDer []byte
	var privPEM []byte

	if key_type == "rsa" {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}

		privPEM = pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(priv),
			},
		)
		publicKeyDer, err = x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			b.Logger().Error("Unable to marshall RSA publicKey %v", err)
			return logical.ErrorResponse(fmt.Sprintf("Unable to get marshall RSA publicKey %v", err)), logical.ErrInvalidRequest
		}

		pubkey = &privatecapb.PublicKey{
			Type: privatecapb.PublicKey_PEM_RSA_KEY,
			Key:  publicKeyDer,
		}
	} else {

		pubkeyCurve := elliptic.P256()
		privecdsa, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)

		x509Encoded, err := x509.MarshalECPrivateKey(privecdsa)
		if err != nil {
			b.Logger().Error("Unable to marshall EC Privatekey %v", err)
			return logical.ErrorResponse(fmt.Sprintf("Unable to marshall EC Privatekey %v", err)), logical.ErrInvalidRequest
		}
		privPEM = pem.EncodeToMemory(
			&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: x509Encoded,
			})
		if err != nil {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}

		publicKeyDer, err = x509.MarshalPKIXPublicKey(&privecdsa.PublicKey)
		if err != nil {
			b.Logger().Error("Unable to get publicKey %v", err)
			return logical.ErrorResponse(fmt.Sprintf("Unable to get publicKey %v", err)), logical.ErrInvalidRequest
		}
		pubkey = &privatecapb.PublicKey{
			Type: privatecapb.PublicKey_PEM_EC_KEY,
			Key:  publicKeyDer,
		}

	}

	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyDer,
		},
	)
	pubkey.Key = pubPem

	var rcfgw privatecapb.ReusableConfigWrapper

	if len(reusable_config) > 0 {
		reusableConfigProject := "privateca-data"
		reusableConfigName := fmt.Sprintf("projects/%s/locations/%s/reusableConfigs/%s", reusableConfigProject, location, reusable_config)
		rcfgw.ConfigValues = &privatecapb.ReusableConfigWrapper_ReusableConfig{
			ReusableConfig: reusableConfigName,
		}
	} else {
		caOptions := &privatecapb.ReusableConfigValues_CaOptions{}
		if is_ca_cert {
			caOptions.IsCa = &wrappers.BoolValue{
				Value: is_ca_cert,
			}
			// TODO: the path length attribute isn't shown in the cert thats issued...
			if v, ok := d.GetOk("max_chain_length"); ok {
				caOptions.MaxIssuerPathLength = &wrappers.Int32Value{
					Value: int32(v.(int)),
				}
			}
		}
		// meh, ther's much more elegant way than iterating like this
		// dont be lazy, sal
		rcfgw.ConfigValues = &privatecapb.ReusableConfigWrapper_ReusableConfigValues{
			ReusableConfigValues: &privatecapb.ReusableConfigValues{
				CaOptions: caOptions,
				KeyUsage: &privatecapb.KeyUsage{
					BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
						DigitalSignature:  contains(key_usages, digital_signature),
						ContentCommitment: contains(key_usages, content_commitment),
						KeyEncipherment:   contains(key_usages, key_encipherment),
						DataEncipherment:  contains(key_usages, data_encipherment),
						KeyAgreement:      contains(key_usages, key_agreement),
						CertSign:          contains(key_usages, cert_sign),
						CrlSign:           contains(key_usages, cert_sign),
						EncipherOnly:      contains(key_usages, encipher_only),
						DecipherOnly:      contains(key_usages, decipher_only),
					},
					ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
						ServerAuth:      contains(extended_key_usages, server_auth),
						ClientAuth:      contains(extended_key_usages, client_auth),
						CodeSigning:     contains(extended_key_usages, code_signing),
						EmailProtection: contains(extended_key_usages, email_protection),
						TimeStamping:    contains(extended_key_usages, time_stamping),
						OcspSigning:     contains(extended_key_usages, ocsp_signing),
					},
				},
			},
		}
	}

	parent := fmt.Sprintf("projects/%s/locations/%s/certificateAuthorities/%s", projectID, location, issuer)
	creq := &privatecapb.CreateCertificateRequest{
		Parent:        parent,
		CertificateId: name,
		Certificate: &privatecapb.Certificate{
			Lifetime: ptypes.DurationProto(validity),
			Labels:   labels,
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: pubkey,
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject: &privatecapb.Subject{
							Organization:       subjectValues["organization"],
							OrganizationalUnit: subjectValues["organizationunit"],
							Locality:           subjectValues["locality"],
							Province:           subjectValues["province"],
							CountryCode:        subjectValues["country"],
						},
						CommonName: subjectValues["cn"],
						SubjectAltName: &privatecapb.SubjectAltNames{
							DnsNames:       dnsSAN,
							Uris:           uriSAN,
							EmailAddresses: emailSAN,
							IpAddresses:    ipSAN,
						},
					},
					ReusableConfig: &rcfgw,
				},
			},
		},
	}

	cresp, err := pcaClient.CreateCertificate(ctx, creq)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"pubcert": cresp.GetPemCertificate(),
			"privkey": string(privPEM),
		},
	}, nil
}

func (b *backend) pathGenerateKeyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var name string

	name = d.Get("name").(string)
	ccfg, err := b.Config(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	issuer := ccfg.Issuer
	projectID := ccfg.Project
	location := ccfg.Location

	pcaClient, closer, err := b.PCAClient(req.Storage)
	if err != nil {
		return nil, err
	}
	defer closer()

	b.Logger().Debug("Attempting to see if cert exists issuer:", issuer, "name:", name)

	parent := fmt.Sprintf("projects/%s/locations/%s/certificateAuthorities/%s/certificates/%s", projectID, location, issuer, name)
	getReq := &privatecapb.GetCertificateRequest{
		Name: parent,
	}
	gcert, err := pcaClient.GetCertificate(ctx, getReq)
	if err != nil {
		b.Logger().Debug("CertificateName doesn't exist..this maybe an anonymous cert, exiting  certspec:", issuer, "name[", name, "]")
		// not sure what to return here, err or nil
		//return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		return &logical.Response{}, nil
	}

	if gcert.RevocationDetails != nil {
		b.Logger().Debug("Certificate already Revoked [", name, "] certspec: [", gcert.RevocationDetails.RevocationState.String, "]")
		// not sure what to return here, err or nil
		//return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		return &logical.Response{}, nil
	}

	b.Logger().Debug("Revoking Certificate", parent)
	crev := &privatecapb.RevokeCertificateRequest{
		Name:   parent,
		Reason: privatecapb.RevocationReason_CESSATION_OF_OPERATION,
	}
	crevresp, err := pcaClient.RevokeCertificate(ctx, crev)
	if err != nil {
		return logical.ErrorResponse("Error revoking certificate +v", err), logical.ErrInvalidRequest
	}

	b.Logger().Debug("Certificate Revoked %s", crevresp.Name)

	return &logical.Response{}, nil
}

func (b *backend) getReusableConfigs(ctx context.Context, pcaClient *privateca.CertificateAuthorityClient, location string) (values []string, err error) {

	var valid_reusable_config []string
	parent := fmt.Sprintf("projects/%s/locations/%s/reusableConfigs", "privateca-data", location)

	rcreq := &privatecapb.ListReusableConfigsRequest{
		Parent: parent,
	}
	it := pcaClient.ListReusableConfigs(ctx, rcreq)
	for {
		cfg, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return []string{}, err
		}
		n := cfg.Name
		ss := strings.Split(n, "/")
		s := ss[len(ss)-1]
		valid_reusable_config = append(valid_reusable_config, s)
	}
	return valid_reusable_config, nil
}
