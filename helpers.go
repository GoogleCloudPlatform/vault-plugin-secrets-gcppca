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
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// withFieldValidator wraps an OperationFunc and validates the user-supplied
// fields match the schema.
func withFieldValidator(f framework.OperationFunc) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		if err := validateFields(req, d); err != nil {
			return nil, logical.CodedError(400, err.Error())
		}
		return f(ctx, req, d)
	}
}

// validateFields verifies that no bad arguments were given to the request.
func validateFields(req *logical.Request, data *framework.FieldData) error {
	var unknownFields []string
	for k := range req.Data {
		if _, ok := data.Schema[k]; !ok {
			unknownFields = append(unknownFields, k)
		}
	}

	switch len(unknownFields) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("unknown field: %s", unknownFields[0])
	default:
		sort.Strings(unknownFields)
		return fmt.Errorf("unknown fields: %s", strings.Join(unknownFields, ","))
	}
}

// errMissingFields is a helper to return an error when required fields are
// missing.
func errMissingFields(f ...string) error {
	return logical.CodedError(400, fmt.Sprintf(
		"missing required field(s): %q", f))
}

// https://stackoverflow.com/questions/28125963/golang-parse-time-duration
var durationRegex = regexp.MustCompile(`P([\d\.]+Y)?([\d\.]+M)?([\d\.]+D)?T?([\d\.]+H)?([\d\.]+M)?([\d\.]+?S)?`)

// ParseDuration converts a ISO8601 duration into a time.Duration
func parseDuration(str string) (time.Duration, error) {
	matches := durationRegex.FindStringSubmatch(str)
	if len(matches) == 0 {
		return 0, errors.New("Invalid duration, must be ISO8601 format")
	}
	years := parseDurationPart(matches[1], time.Hour*24*365)
	months := parseDurationPart(matches[2], time.Hour*24*30)
	days := parseDurationPart(matches[3], time.Hour*24)
	hours := parseDurationPart(matches[4], time.Hour)
	minutes := parseDurationPart(matches[5], time.Second*60)
	seconds := parseDurationPart(matches[6], time.Second)

	return time.Duration(years + months + days + hours + minutes + seconds), nil
}

func parseDurationPart(value string, unit time.Duration) time.Duration {
	if len(value) != 0 {
		if parsed, err := strconv.ParseFloat(value[:len(value)-1], 64); err == nil {
			return time.Duration(float64(unit) * parsed)
		}
	}
	return 0
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func toInt32(in int) *int32 {
	q := int32(in)
	return &q
}
