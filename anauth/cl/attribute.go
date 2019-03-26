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
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/spf13/viper"
)

type Attrs struct {
	// attributes that are Known to the credential receiver and issuer
	Known []*big.Int
	// attributes which are Known only to the credential receiver
	Hidden []*big.Int
	// attributes for which the issuer knows only commitment
	Committed []*big.Int
}

func NewAttrs(known, committed, hidden []*big.Int) *Attrs {
	return &Attrs{
		Known:     known,
		Hidden:    hidden,
		Committed: committed,
	}
}

func (a *Attrs) join() []*big.Int {
	all := make([]*big.Int, 0)
	all = append(all, a.Known...)
	all = append(all, a.Hidden...)
	all = append(all, a.Committed...)
	return all
}

// AttrCount holds the number of Known, Committed and
// Hidden parameters.
type AttrCount struct {
	Known     int
	Committed int
	Hidden    int
}

func NewAttrCount(known, committed, hidden int) *AttrCount {
	return &AttrCount{
		Known:     known,
		Committed: committed,
		Hidden:    hidden,
	}
}

func (c *AttrCount) String() string {
	return fmt.Sprintf("Known: %d\ncommitted: %d\nhidden: %d\n",
		c.Known, c.Committed, c.Hidden)
}

// CredAttr represents an attribute for the CL scheme.
type CredAttr interface {
	getIndex() int
	getValue() interface{}
	getCond() AttrCond
	UpdateValue(interface{}) error
	internalValue() *big.Int
	updateInternalValue(*big.Int) error
	setInternalValue() error
	isKnown() bool
	hasVal() bool
	Name() string
	String() string

	Validatable
}

// Validatable validates against a credential attribute.
type Validatable interface{
	ValidateAgainst(interface{}) (bool, error)
}

type AttrCond int

const (
	lessThan AttrCond = iota
	lessThanOrEqual
	greaterThan
	greaterThanOrEqual
	equal
	none
)

var attrCondStr = []string{"lt", "lte", "gt", "gte", "equal", "none"}

func (c AttrCond) String() string {
	return attrCondStr[c]
}

func parseAttrCond(cond string) (AttrCond, error) {
	for i, c := range attrCondStr {
		if cond == c  {
			return AttrCond(i), nil
		}
	}

	return -1, fmt.Errorf("invalid condition '%s'", cond)
}

// Attr is part of a credential (RawCredential). In the case of digital identity credential,
// attributes could be for example name, Gender, Date of Birth. In the case of a credential allowing
// access to some internet service (like electronic newspaper), attributes could be
// Type (for example only news related to politics) of the service and Date of Expiration.
type Attr struct {
	name   string
	Known  bool
	ValSet bool
	Val    *big.Int
	cond   AttrCond
	Index  int
}

func newAttr(name string, known bool) *Attr {
	return &Attr{
		name:   name,
		Known:  known,
		ValSet: false,
	}
}

func (a *Attr) getIndex() int  {
	return a.Index
}

func (a *Attr) getCond() AttrCond {
	return a.cond
}

func (a *Attr) isKnown() bool {
	return a.Known
}

func (a *Attr) internalValue() *big.Int {
	return a.Val
}

func (a *Attr) hasVal() bool {
	return a.ValSet
}

func (a *Attr) Name() string {
	return a.name
}

func (a *Attr) String() string {
	tag := "Known"
	if !a.isKnown() {
		tag = "revealed"
	}
	return fmt.Sprintf("%s (%s)", a.name, tag)
}

type Int64Attr struct {
	Val int64
	*Attr
}

func NewEmptyInt64Attr(name string, known bool) *Int64Attr {
	return &Int64Attr{
		Attr: newAttr(name, known),
	}
}

func NewInt64Attr(name string, val int64, known bool) (*Int64Attr,
	error) {
	a := &Int64Attr{
		Val:  val,
		Attr: newAttr(name, known),
	}
	if err := a.setInternalValue(); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *Int64Attr) setInternalValue() error {
	a.Attr.Val = big.NewInt(int64(a.Val)) // FIXME
	a.ValSet = true
	return nil
}

func (a *Int64Attr) updateInternalValue(val *big.Int) error {
	v, err := strconv.Atoi(val.String())
	if err != nil {
		return err
	}
	a.Val = int64(v)
	return nil
 }

func (a *Int64Attr) getValue() interface{} {
	return a.Val
}

func (a *Int64Attr) UpdateValue(n interface{}) error {
	switch n.(type) {
	case int:
		a.Val = int64(n.(int))
	case int64:
		a.Val = n.(int64)
	}
	return a.setInternalValue()
}

func (a *Int64Attr) ValidateAgainst(v interface{}) (bool, error) {
	actual, ok := v.(int64)
	if !ok {
		return false, fmt.Errorf("value provided for '%s' is not int64",
			a.Name())
	}

	var res bool

	switch a.cond {
	case greaterThan:
		res = actual > a.Val
	case greaterThanOrEqual:
		res = actual >= a.Val
	case lessThan:
		res = actual < a.Val
	case lessThanOrEqual:
		res = actual <= a.Val
	case equal:
		res = actual == a.Val
	default:
		return false, errors.New("invalid condition")
	}

	return res, nil
}

func (a *Int64Attr) String() string {
	return fmt.Sprintf("%s, type = %T", a.Attr.String(), a.Val)
}

type StrAttr struct {
	Val string
	*Attr
}

func NewEmptyStrAttr(name string, known bool) *StrAttr {
	return &StrAttr{
		Attr: newAttr(name, known),
	}
}

func NewStrAttr(name, val string, known bool) (*StrAttr,
	error) {
	a := &StrAttr{
		Val:  val,
		Attr: newAttr(name, known),
	}
	if err := a.setInternalValue(); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *StrAttr) setInternalValue() error {
	a.Attr.Val = new(big.Int).SetBytes([]byte(a.Val)) // FIXME
	a.ValSet = true
	return nil
}

func (a *StrAttr) updateInternalValue(val *big.Int) error {
	v := string(val.Bytes())
	a.Val = v
	return nil
}

func (a *StrAttr) getValue() interface{} {
	return a.Val
}

func (a *StrAttr) UpdateValue(s interface{}) error {
	a.Val = s.(string)
	return a.setInternalValue()
}

func (a *StrAttr) ValidateAgainst(v interface{}) (bool, error) {
	actual, ok := v.(string)
	if !ok {
		return false, fmt.Errorf("value provided for '%s' is not string",
			a.Name())
	}

	if a.cond != equal {
		return false, errors.New("invalid condition")
	}

	return actual == a.Val, nil
}

func (a *StrAttr) String() string {
	return fmt.Sprintf("%s, type = %T", a.Attr.String(), a.Val)
}

// FIXME make nicer
// Hook to organization?
func parseAttrs(v *viper.Viper) ([]CredAttr, *AttrCount, error) {
	if !v.IsSet("attributes") {
		return nil, nil, fmt.Errorf("missing attributes declaration")
	}

	specs := v.GetStringMap("attributes")
	attrs := make([]CredAttr, len(specs))

	var nKnown, nCommitted int

	for name, val := range specs { // TODO enforce proper ordering with Index
		data, ok := val.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("invalid configuration")
		}

		index, ok := data["index"]
		if !ok {
			return nil, nil, fmt.Errorf("missing attribute index")
		}
		i, ok := index.(int)
		if !ok {
			return nil, nil, fmt.Errorf("Index must be an integer")
		}
		if i >= len(attrs) {
			return nil, nil,
			fmt.Errorf("Index too large for the provided number of attributes")
		}
		if attrs[i] != nil {
			return nil, nil,
				fmt.Errorf("duplicate index")
		}


		t, ok := data["type"]
		if !ok {
			return nil, nil, fmt.Errorf("missing type specifier")
		}

		known := true
		k, ok := data["known"]
		if ok {
			res, err := strconv.ParseBool(k.(string))
			if err != nil {
				return nil, nil, fmt.Errorf("Known must be true or false")
			}
			known = res
		}

		if known {
			nKnown++
		} else {
			nCommitted++
		}

		var condition AttrCond
		cond, ok := data["cond"]
		if !ok {
			condition = none
		} else {
			c, err := parseAttrCond(cond.(string))
			if err != nil {
				return nil, nil, err
			}
			condition = c
		}

		switch t {
		case "string":
			a, err := NewStrAttr(name, "", known) // FIXME
			if err != nil {
				return nil, nil, err
			}
			a.cond = condition
			attrs[i] = a
			a.Index = i
		case "int64":
			a, err := NewInt64Attr(name, 0, known) // FIXME
			if err != nil {
				return nil, nil, err
			}
			a.cond = condition
			attrs[i] = a
			a.Index = i
		default:
			return nil, nil, fmt.Errorf("unsupported attribute type: %s", t)
		}

		i++
	}

	// TODO Hidden params
	return attrs, NewAttrCount(nKnown, nCommitted, 0), nil
}
