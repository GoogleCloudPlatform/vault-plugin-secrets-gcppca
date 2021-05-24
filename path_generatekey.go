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

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/api/iterator"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
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
	valid_certificate_templates = []string{} // derived
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
			"certificate_template": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Certificate Template to use`,
			},
			"issuing_certificate_authority": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Optional. The resource ID of the CertificateAuthority that should issue the certificate. `,
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
	var certificate_template string
	var validity time.Duration
	var labels map[string]string
	var is_ca_cert bool
	var issuingCertificateAuthority string

	name = d.Get("name").(string)

	b.Logger().Debug(fmt.Sprintf("Start generatecert for %s", name))

	// First read the configuration settings that define the specifications of the CA
	cfg, err := b.Config(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	pool := cfg.Pool
	projectID := cfg.Project
	location := cfg.Location

	if pool == "" || projectID == "" || location == "" {
		return logical.ErrorResponse("Configuration settings not found: CAPool, ProjectID and Location must be set in <mount>/config"), logical.ErrInvalidRequest
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

	// certificate_templates can reside in any other project.   For the sake of configuration simplicity,
	// we can comment out the following and skip the check.  If the referenced template does not exist, the
	// error isn't particularly helpful: "rpc error: code = NotFound desc = Requested entity was not found."
	valid_certificate_templates, err := b.getCertificateTemplates(ctx, pcaClient, projectID, location)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Could not recall certificate Templates from project %s", projectID)), logical.ErrInvalidRequest
	}

	if v, ok := d.GetOk("certificate_template"); ok {
		if !contains(valid_certificate_templates, v.(string)) {
			return logical.ErrorResponse("Invalid reusable configs, must one of %v", valid_certificate_templates), logical.ErrInvalidRequest
		}
		certificate_template = v.(string)
	}

	if v, ok := d.GetOk("issuing_certificate_authority"); ok {
		issuingCertificateAuthority = v.(string)
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
			if !contains(valid_key_usages, usage) {
				return logical.ErrorResponse("Invalid extended_key_usages, must one of ", valid_extended_key_usages), logical.ErrInvalidRequest
			}
		}
		extended_key_usages = v.([]string)
	}

	if len(certificate_template) > 0 && (len(key_usages) > 0 || len(extended_key_usages) > 0) {
		b.Logger().Error("Either certificate_template or (key_usages|extended_key_usage) must be specified")
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

	var pubPem []byte
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

		pubPem = pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: publicKeyDer,
			},
		)
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
		pubPem = pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: publicKeyDer,
			},
		)

	}

	parent := fmt.Sprintf("projects/%s/locations/%s/caPools/%s", projectID, location, pool)

	var creq privatecapb.CreateCertificateRequest

	var rcfgw privatecapb.X509Parameters

	if len(certificate_template) > 0 {

		creq = privatecapb.CreateCertificateRequest{
			Parent:                        parent,
			CertificateId:                 name,
			IssuingCertificateAuthorityId: issuingCertificateAuthority,
			Certificate: &privatecapb.Certificate{
				Lifetime:            ptypes.DurationProto(validity),
				Labels:              labels,
				CertificateTemplate: certificate_template,
				CertificateConfig: &privatecapb.Certificate_Config{
					Config: &privatecapb.CertificateConfig{
						PublicKey: &privatecapb.PublicKey{
							Format: privatecapb.PublicKey_PEM,
							Key:    pubPem,
						},
						X509Config: &privatecapb.X509Parameters{},
						SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
							Subject: &privatecapb.Subject{
								Organization:       subjectValues["organization"],
								OrganizationalUnit: subjectValues["organizationunit"],
								Locality:           subjectValues["locality"],
								Province:           subjectValues["province"],
								CountryCode:        subjectValues["country"],
								CommonName:         subjectValues["cn"],
							},
							SubjectAltName: &privatecapb.SubjectAltNames{
								DnsNames:       dnsSAN,
								Uris:           uriSAN,
								EmailAddresses: emailSAN,
								IpAddresses:    ipSAN,
							},
						},
					},
				},
			},
		}

	} else {
		caOptions := &privatecapb.X509Parameters_CaOptions{}
		if is_ca_cert {
			caOptions.IsCa = &is_ca_cert
			// TODO: the path length attribute isn't shown in the cert thats issued...
			if v, ok := d.GetOk("max_chain_length"); ok {
				caOptions.MaxIssuerPathLength = toInt32(v.(int))
			}
		}
		// meh, ther's much more elegant way than iterating like this
		// dont be lazy, sal
		rcfgw = privatecapb.X509Parameters{

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
			CaOptions: &privatecapb.X509Parameters_CaOptions{
				IsCa: &is_ca_cert,
			},
		}
		creq = privatecapb.CreateCertificateRequest{
			Parent:                        parent,
			CertificateId:                 name,
			IssuingCertificateAuthorityId: issuingCertificateAuthority,
			Certificate: &privatecapb.Certificate{
				Lifetime: ptypes.DurationProto(validity),
				Labels:   labels,
				CertificateConfig: &privatecapb.Certificate_Config{
					Config: &privatecapb.CertificateConfig{
						PublicKey: &privatecapb.PublicKey{
							Format: privatecapb.PublicKey_PEM,
							Key:    pubPem,
						},
						SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
							Subject: &privatecapb.Subject{
								Organization:       subjectValues["organization"],
								OrganizationalUnit: subjectValues["organizationunit"],
								Locality:           subjectValues["locality"],
								Province:           subjectValues["province"],
								CountryCode:        subjectValues["country"],
								CommonName:         subjectValues["cn"],
							},
							SubjectAltName: &privatecapb.SubjectAltNames{
								DnsNames:       dnsSAN,
								Uris:           uriSAN,
								EmailAddresses: emailSAN,
								IpAddresses:    ipSAN,
								// CustomSans is just a sample placeholder below because i do not
								// know how best to map a vault config into a complex proto
								// TODO: figure out how to specify customSans in vault config.
								//       maybe serialized b64  []*X509Extension serialized?
								// CustomSans: []*privatecapb.X509Extension{{
								// 	ObjectId: &privatecapb.ObjectId{
								// 		ObjectIdPath: []int32{},
								// 	},
								// 	Critical: false,
								// 	Value: []byte(""),
								// }},
							},
						},
						X509Config: &rcfgw,
					},
				},
			},
		}
	}

	cresp, err := pcaClient.CreateCertificate(ctx, &creq)
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

	caPool := ccfg.Pool
	projectID := ccfg.Project
	location := ccfg.Location

	pcaClient, closer, err := b.PCAClient(req.Storage)
	if err != nil {
		return nil, err
	}
	defer closer()

	b.Logger().Debug("Attempting to see if cert exists issuer:", caPool, "name:", name)

	parent := fmt.Sprintf("projects/%s/locations/%s/caPools/%s/certificates/%s", projectID, location, caPool, name)
	getReq := &privatecapb.GetCertificateRequest{
		Name: parent,
	}
	gcert, err := pcaClient.GetCertificate(ctx, getReq)
	if err != nil {
		b.Logger().Debug("CertificateName doesn't exist..this maybe an anonymous cert, exiting  certspec:", caPool, "name[", name, "]")
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

func (b *backend) getCertificateTemplates(ctx context.Context, pcaClient *privateca.CertificateAuthorityClient, projectID string, location string) (values []string, err error) {

	var valid_certificate_templates []string
	parent := fmt.Sprintf("projects/%s/locations/%s/certificateTemplates", projectID, location)

	rcreq := &privatecapb.ListCertificateTemplatesRequest{
		Parent: parent,
	}
	it := pcaClient.ListCertificateTemplates(ctx, rcreq)
	for {
		cfg, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return []string{}, err
		}
		valid_certificate_templates = append(valid_certificate_templates, cfg.Name)
	}
	return valid_certificate_templates, nil
}
