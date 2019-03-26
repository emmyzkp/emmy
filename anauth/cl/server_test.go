/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package cl

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tests that server cannot be started when attribute specification
// and server's public key do not agree with each other.
func TestNewServer_InvalidConfig(t *testing.T) {
	// we don't expect any attributes
	v := viper.New()
	v.Set("attributes", map[string]interface{}{})

	tests := []struct {
		desc      string
		known     int
		committed int
		hidden    int
	}{
		{"KnownMismatch", 1, 0, 0},
		{"CommittedMismatch", 0, 1, 0},
		{"HiddenMismatch", 0, 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			keys, err := GenerateKeyPair(
				GetDefaultParamSizes(),
				NewAttrCount(tt.known, tt.committed, tt.hidden),
			)

			require.NoError(t, err)

			_, err = NewServer(nil, keys, v)
			assert.Error(t, err)
		})
	}
}
