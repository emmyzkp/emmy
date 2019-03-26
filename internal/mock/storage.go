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

package mock

// RegKeyDB mocks storage of registration keys. It is a
// slice that will hold the keys.
type RegKeyDB struct {
	data []string
}

// insert inserts a registration key to RegKeyDB,
// if it's not already present.
func (m *RegKeyDB) Insert(key string) {
	alreadyPresent := false
	for _, k := range m.data {
		if k == key {
			alreadyPresent = true
			break
		}
	}
	if !alreadyPresent {
		m.data = append(m.data, key)
	}
}

// CheckRegistrationKey checks for the presence of registration
// key key, removing it and returning success if it was present.
// If the key is not present in the slice, it returns false.
func (m *RegKeyDB) CheckRegistrationKey(key string) (bool, error) {
	for i, regKey := range m.data {
		if key == regKey {
			m.data = append(m.data[:i], m.data[i+1:]...) // remove i
			return true, nil
		}
	}

	return false, nil
}
