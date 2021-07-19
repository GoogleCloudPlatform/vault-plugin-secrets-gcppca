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

package version

import "fmt"

const (
	// Name is the name of the plugin.
	Name = "vault-plugin-secrets-gcppca"

	// Version is the version of the release.
	Version = "1.0.3"
)

var (
	// GitCommit is the specific git commit of the plugin. This is completed by
	// the compiler.
	GitCommit string

	// HumanVersion is the human-formatted version of the plugin.
	HumanVersion = fmt.Sprintf("%s v%s (%s)", Name, Version, GitCommit)
)
