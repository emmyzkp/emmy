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

package compat

import (
	"math/big"

	"fmt"

	"github.com/emmyzkp/emmy/anauth/psys"
)

// Pseudonym represents an equivalent of pseudsys.Nym, but has string
// field types to overcome type restrictions of Go language binding tools.
type Pseudonym struct {
	A string
	B string
}

func NewPseudonym(a, b string) *Pseudonym {
	return &Pseudonym{
		A: a,
		B: b,
	}
}

// getNativeType translates compatibility Nym to emmy's native pseudsys.Nym.
func (p *Pseudonym) getNativeType() (*psys.Nym, error) {
	a, aOk := new(big.Int).SetString(p.A, 10)
	b, bOk := new(big.Int).SetString(p.B, 10)
	if !aOk || !bOk {
		return nil, fmt.Errorf("nym.A or nym.B: %s", ArgsConversionError)
	}

	pseudonym := psys.NewNym(a, b)
	return pseudonym, nil
}

// CACertificate represents an equivalent of pseudsys.CACert, but has string
// field types to overcome type restrictions of Go language binding tools.
type CACertificate struct {
	BlindedA string
	BlindedB string
	R        string
	S        string
}

func NewCACertificate(blindedA, blindedB, r, s string) *CACertificate {
	return &CACertificate{
		BlindedA: blindedA,
		BlindedB: blindedB,
		R:        r,
		S:        s,
	}
}

func (c *CACertificate) toNativeType() (*psys.CACert, error) {
	blindedA, blindedAOk := new(big.Int).SetString(c.BlindedA, 10)
	blindedB, blindedBOk := new(big.Int).SetString(c.BlindedB, 10)
	r, rOk := new(big.Int).SetString(c.R, 10)
	s, sOk := new(big.Int).SetString(c.S, 10)
	if !blindedAOk || !blindedBOk || !rOk || !sOk {
		return nil, fmt.Errorf("certificate's blindedA, blindedB, r or s: %s",
			ArgsConversionError)
	}

	certificate := psys.NewCACert(blindedA, blindedB, r, s)
	return certificate, nil
}

// CAClient wraps around client.CAClient to conform to
// type restrictions of Go language binding tools. It exposes the same set of methods as
// client.CAClient.
type PseudonymsysCAClient struct {
	*psys.CAClient
}

func NewPseudonymsysCAClient(g *SchnorrGroup) (*PseudonymsysCAClient, error) {
	// Translate SchnorrGroup
	group, err := g.toNativeType()
	if err != nil {
		return nil, err
	}

	return &PseudonymsysCAClient{
		CAClient: psys.NewCAClient(group),
	}, nil
}

func (c *PseudonymsysCAClient) Connect(conn *Connection) {
	c.CAClient.Connect(conn.ClientConn)
}

func (c *PseudonymsysCAClient) GenerateMasterNym(secret string) (*Pseudonym, error) {
	// Translate secret
	s, sOk := new(big.Int).SetString(secret, 10)
	if !sOk {
		return nil, fmt.Errorf("secret (%s): %s", secret, ArgsConversionError)
	}
	masterNym := c.CAClient.GenerateMasterNym(s)
	return NewPseudonym(masterNym.A.String(), masterNym.B.String()), nil
}

func (c *PseudonymsysCAClient) GenerateCertificate(userSecret string,
	nym *Pseudonym) (*CACertificate, error) {
	// Translate secret
	secret, secretOk := new(big.Int).SetString(userSecret, 10)
	if !secretOk {
		return nil, fmt.Errorf("secret (%s): %s", secret, ArgsConversionError)
	}

	// Translate Pseudonym
	pseudonym, err := nym.getNativeType()
	if err != nil {
		return nil, err
	}

	// Call CAClient client with translated parameters
	cert, err := c.CAClient.GenerateCertificate(secret, pseudonym)
	if err != nil {
		return nil, err
	}

	return NewCACertificate(
		cert.BlindedA.String(),
		cert.BlindedB.String(),
		cert.R.String(),
		cert.S.String()), nil
}
