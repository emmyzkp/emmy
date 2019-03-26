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

	"github.com/stretchr/testify/assert"
)

func TestRawCred_EmptyAttributeName(t *testing.T) {
	nAttrs := NewAttrCount(1, 1, 1)
	rc := NewRawCred(nAttrs)
	err := rc.addEmptyInt64Attr("", 0, true)
	assert.Error(t, err)
}

func TestRawCred_ExceedKnownAttrsCount(t *testing.T) {
	nAttrs := NewAttrCount(0, 0, 0)
	rc := NewRawCred(nAttrs)
	err := rc.addEmptyInt64Attr("a", 0, true)
	assert.Error(t, err)
}

func TestRawCred_ExceedCommittedAttrsCount(t *testing.T) {
	nAttrs := NewAttrCount(0, 0, 0)
	rc := NewRawCred(nAttrs)
	err := rc.addEmptyInt64Attr("a", 0, false)
	assert.Error(t, err)
}

func TestRawCred_AddInt64Attr(t *testing.T) {
	c := NewRawCred(NewAttrCount(1, 0, 0))
	err := c.addEmptyInt64Attr("Age", 0, true)
	assert.NoError(t, err)
	assert.Len(t, c.GetAttrs(), 1)
}

// checks that when a duplicate parameter is created, error is
// reported.
func TestRawCred_AddDuplicate(t *testing.T) {
	c := NewRawCred(NewAttrCount(2, 0, 0))
	_ = c.addEmptyInt64Attr("a", 0, true)
	err := c.addEmptyInt64Attr("a", 0, false)
	assert.Error(t, err)
}

// TODO case insensitivity?

// check that an error is raised when we're trying to access an
// attribute that does not exist in the credential.
func TestRawCred_GetAttributeInvalid(t *testing.T) {
	rc := NewRawCred(NewAttrCount(1, 0, 0))
	a, err := rc.GetAttr("test")
	assert.Error(t, err)
	assert.Nil(t, a)
}
