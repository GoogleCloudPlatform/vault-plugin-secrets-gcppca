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

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/salrashid123/vault-plugin-secrets-gcppca/version"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		log.Fatal("missing argument")
	}

	switch args[0] {
	case "name":
		fmt.Printf("%s", version.Name)
	case "version":
		fmt.Printf("%s", version.Version)
	default:
		log.Fatalf("unknown arg %q", args[0])
	}
}
