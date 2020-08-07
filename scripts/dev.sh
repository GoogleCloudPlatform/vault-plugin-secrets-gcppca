#!/usr/bin/env bash
# Copyright 2020 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

export GRPC_GO_LOG_VERBOSITY_LEVEL=2
export GRPC_GO_LOG_SEVERITY_LEVEL=info

pkill vault || true

make dev
mkdir -p bin/
cp "$GOPATH/bin/vault-plugin-secrets-gcppca" bin/

vault server \
  -log-level=warn \
  -dev \
  -dev-plugin-dir="$(pwd)/bin" &
VAULT_PID=$!
sleep 2



export SHASUM=$(shasum -a 256 "bin/vault-plugin-secrets-gcppca" | cut -d " " -f1)

vault plugin register \
    -sha256="${SHASUM}" \
    -command="vault-plugin-secrets-gcppca" \
    secret vault-plugin-secrets-gcppca

vault secrets enable -path="gcppca" \
   --description='Vault CA Service Plugin' \
   --plugin-name='vault-plugin-secrets-gcppca' plugin