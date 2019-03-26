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

package anauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/go-redis/redis"
)

// SessStorer stores arbitrary data associated with the
// authenticated session to the storage backend, returning
// error in case the data could not be stored.
type SessStorer interface{
	Store(string) error
}

// SessManager generates a new session key.
// It returns a string containing the generated session key
// or an error in case session key could not be generated.
type SessManager interface {
	GenerateSessionKey() (*string, error)
}

// MIN_SESSION_KEY_BYTE_LEN represents the minimal allowed length
// of the session key in bytes, for security reasons.
const MIN_SESSION_KEY_BYTE_LEN = 24

// RandSessionKeyGen generates session keys of the desired byte
// length from random bytes.
type RandSessionKeyGen struct {
	byteLen int
}

// NewRandSessionKeyGen creates a new RandSessionKeyGen instance.
// The new instance will be configured to generate session keys
// with exactly byteLen bytes. For security reasons, the function
// checks the byteLen against the value of MIN_SESSION_KEY_BYTE_LEN.
// If the provided byteLen is smaller than MIN_SESSION_KEY_BYTE_LEN,
// an error is set and the returned RandSessionKeyGen is configured
// to use MIN_SESSION_KEY_BYTE_LEN instead of the provided byteLen.
func NewRandSessionKeyGen(byteLen int) (*RandSessionKeyGen, error) {
	var err error
	if byteLen < MIN_SESSION_KEY_BYTE_LEN {
		err = fmt.Errorf("desired length of the session key (%d B) is too short, falling back to %d B",
			byteLen, MIN_SESSION_KEY_BYTE_LEN)
		byteLen = MIN_SESSION_KEY_BYTE_LEN
	}
	return &RandSessionKeyGen{
		byteLen: byteLen,
	}, err
}

// GenerateSessionKey produces a secure random session key and returns
// its base64-encoded representation that is URL-safe.
// It reports an error in case random byte sequence could not be generated.
func (m *RandSessionKeyGen) GenerateSessionKey() (*string, error) {
	randBytes := make([]byte, m.byteLen)

	// reads m.byteLen random bytes (e.g. len(randBytes)) to randBytes array
	_, err := rand.Read(randBytes)

	// an error may occur if the system's secure RNG doesn't function properly, in which case
	// we can't generate a secure session key
	if err != nil {
		return nil, err
	}

	sessionKey := base64.URLEncoding.EncodeToString(randBytes)
	return &sessionKey, nil
}

type RedisSessStorer struct {
	*redis.Client
}

func NewRedisSessStorer(c *redis.Client) *RedisSessStorer {
	return &RedisSessStorer{
		Client: c,
	}
}

func (s *RedisSessStorer) Store(key string) error {
	return s.Client.Set(key, nil, 0).Err()
}