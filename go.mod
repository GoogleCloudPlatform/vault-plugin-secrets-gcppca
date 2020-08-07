module github.com/salrashid123/vault-plugin-secrets-gcppca

go 1.12

require (
	cloud.google.com/go v0.56.0
	cloud.google.com/go/security/privateca/apialpha1 v0.0.0
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/gammazero/deque v0.0.0-20190130191400-2afb3858e9c7 // indirect
	github.com/gammazero/workerpool v0.0.0-20190406235159-88d534f22b56
	github.com/golang/protobuf v1.3.5
	github.com/google/uuid v1.1.1
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-hclog v0.12.0
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hashicorp/vault/api v1.0.5-0.20200215224050-f6547fa8e820
	github.com/hashicorp/vault/sdk v0.1.14-0.20200215224050-f6547fa8e820
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/jeffchao/backoff v0.0.0-20140404060208-9d7fd7aa17f2
	github.com/kr/pretty v0.1.0 // indirect
	github.com/satori/go.uuid v1.2.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/text v0.3.2 // indirect
	google.golang.org/api v0.23.0
	google.golang.org/genproto v0.0.0-20200331122359-1ee6d9798940
	google.golang.org/genproto/googleapis/cloud/security/privateca/v1alpha1 v0.0.0
	google.golang.org/grpc v1.28.0
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect

)

replace cloud.google.com/go/security/privateca/apialpha1 => ./lib/cloud.google.com/go/security/privateca/apiv1alpha1

replace google.golang.org/genproto/googleapis/cloud/security/privateca/v1alpha1 => ./lib/google.golang.org/genproto/googleapis/cloud/security/privateca/v1alpha1
