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
	"fmt"
	"math/big"
)

// RawCred represents a credential to be used by application that
// executes the scheme to prove possesion of an anonymous credential.
type RawCred struct {
	Attrs       map[int]CredAttr
	AttrIndices map[string]int
	AttrCount   *AttrCount
}

func NewRawCred(c *AttrCount) *RawCred {
	return &RawCred{
		Attrs:       make(map[int]CredAttr),
		AttrIndices: make(map[string]int),
		AttrCount:   c,
	}
}

func(c *RawCred) String() string {
	return fmt.Sprintf("%v", c.AttrIndices)
}

// missingAttrs checks whether any of the attributes
// associated with this raw credential was left unset by the client.
func (c *RawCred) missingAttrs() error {
	for _, a := range c.Attrs {
		if !a.hasVal() {
			fmt.Println(a.Name(), " missing")
			return fmt.Errorf(a.Name())
		}
	}
	return nil
}

func (c *RawCred) GetAttr(name string) (CredAttr, error) {
	i, ok := c.AttrIndices[name]
	if !ok {
		return nil, fmt.Errorf("no attribute %s in this credential", name)
	}
	return c.Attrs[i], nil
}

func (c *RawCred) UpdateAttr(name string, val interface{}) error {
	attr, err := c.GetAttr(name)
	if err != nil {
		return err
	}

	if err = attr.UpdateValue(val); err != nil {
		return err
	}

	i := c.AttrIndices[name]
	c.Attrs[i] = attr
	return nil
}

func (c *RawCred) addEmptyStrAttr(name string, i int, known bool) error {
	if err := c.validateAttr(name, known); err != nil {
		return err
	}
	//i := len(c.Attrs)
	empty := NewEmptyStrAttr(name, known)
	empty.Index = i
	c.insertAttr(i, empty)

	return nil
}

func (c *RawCred) addEmptyInt64Attr(name string, i int, known bool) error {
	if err := c.validateAttr(name, known); err != nil {
		return err
	}
	//i := len(c.Attrs)
	empty := NewEmptyInt64Attr(name, known)
	empty.Index = i
	c.insertAttr(i, empty)
	return nil
}

// GetKnownVals returns *big.Int values of Known attributes.
// The returned elements are ordered by attribute's Index.
func (c *RawCred) GetKnownVals() []*big.Int {
	var values []*big.Int
	for i := 0; i < len(c.Attrs); i++ { // avoid range to have attributes in proper order
		attr := c.Attrs[i]
		if attr.isKnown() {
			values = append(values, attr.internalValue())
		}
	}

	return values
}

// GetCommittedVals returns *big.Int values of Committed attributes.
// The returned elements are ordered by attribute's Index.
func (c *RawCred) GetCommittedVals() []*big.Int {
	var values []*big.Int
	for i := 0; i < len(c.Attrs); i++ { // avoid range to have attributes in
		// proper order
		attr := c.Attrs[i]
		if !attr.isKnown() {
			values = append(values, attr.internalValue())
		}
	}

	return values
}

func (c *RawCred) GetAttrs() map[int]CredAttr {
	return c.Attrs
}

func (c *RawCred) insertAttr(i int, a CredAttr) {
	c.AttrIndices[a.Name()] = i
	c.Attrs[i] = a
}

func (c *RawCred) validateAttr(name string, known bool) error {
	if known && len(c.GetKnownVals()) >= c.AttrCount.Known {
		return fmt.Errorf("Known attributes exhausted")
	}

	if !known && len(c.GetCommittedVals()) >= c.AttrCount.Committed {
		return fmt.Errorf("Committed attributes exhausted")
	}

	if name == "" {
		return fmt.Errorf("attribute's name cannot be empty")
	}

	if c.hasAttr(name) {
		return fmt.Errorf("duplicate attribute, ignoring")
	}

	return nil
}

func (c *RawCred) hasAttr(name string) bool {
	for _, a := range c.Attrs {
		if name == a.Name() {
			return true
		}
	}

	return false
}
