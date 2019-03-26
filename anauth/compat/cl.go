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
	"bytes"
	"encoding/gob"
	"math/big"

	"github.com/emmyzkp/emmy/anauth/cl"
	"github.com/emmyzkp/emmy/anauth/cl/clpb"
)

type CLClient struct {
	*cl.Client
}

func NewCLClient(conn *Connection) *CLClient {
	return &CLClient{
		Client: cl.NewClient(conn.ClientConn),
	}
}

type CLPublicParams struct {
	PubKey  *CLPubKey
	Config  *CLParams
	RawCred *CLRawCred
}

type Commitment struct {
	data []byte
}

type CLRevealedAttrs struct {
	attrs []string
}

func NewCLRevealedAttrs() *CLRevealedAttrs {
	return &CLRevealedAttrs{
		attrs: make([]string, 0),
	}
}

func (a *CLRevealedAttrs) Add(attr string) {
	a.attrs = append(a.attrs, attr)
}

func (c *CLClient) ProveCred(cm *CLCredManager, cred *CLCred,
	revealed *CLRevealedAttrs) (string, error) {
	sessKey, err := c.Client.ProveCredential(cm.CredManager,
		cred.Cred, revealed.attrs)

	if err != nil {
		return "<INVALID>", err
	}

	return *sessKey, nil
}

type CLStringAttribute struct {
	*cl.StrAttr
}

type CLLongAttribute struct {
	*cl.Int64Attr
}

type CLRawCred struct {
	cred *cl.RawCred
}

func NewCLRawCred(bytes []byte) (*CLRawCred, error) {
	// register concrete types that implement cl.CredAttr interface
	gob.Register(&cl.Int64Attr{})
	gob.Register(&cl.StrAttr{})

	var cred cl.RawCred
	if err := fromBytes(bytes, &cred); err != nil {
		return nil, err
	}
	return &CLRawCred{
		cred: &cred,
	}, nil
}

func (c *CLRawCred) GetAttributeNames() []string {
	attrs := make([]string, 0)
	for _, a := range c.cred.GetAttrs() {
		attrs = append(attrs, a.Name())
	}
	return attrs
}

func (c *CLRawCred) SetStringAttribute(name, val string) error {
	if err := c.cred.UpdateAttr(name, val); err != nil {
		return err
	}
	return nil
}

func (c *CLRawCred) SetLongAttribute(name string, val int64) error {
	if err := c.cred.UpdateAttr(name, val); err != nil {
		return err
	}
	return nil
}

func (c *CLRawCred) Bytes() ([]byte, error) {
	// register concrete types that implement cl.CredAttr interface
	gob.Register(&cl.Int64Attr{})
	gob.Register(&cl.StrAttr{})
	return intoBytes(c.cred)
}

type CLCred struct {
	*cl.Cred
}

func NewCLCred(bytes []byte) (*CLCred, error) {
	var cred cl.Cred
	if err := fromBytes(bytes, &cred); err != nil {
		return nil, err
	}
	return &CLCred{
		Cred: &cred,
	}, nil
}

func (c *CLCred) Bytes() ([]byte, error) {
	return intoBytes(c.Cred)
}

type PedersenParams struct {
	Group SchnorrGroup
	H     []byte
	a     []byte
}

type CLParams struct {
	*clpb.Params
}

type CLPubKey struct {
	*cl.PubKey
}

func (k *CLPubKey) GenerateMasterSecret() []byte {
	return k.PubKey.GenerateUserMasterSecret().Bytes()
}

type CLCredManager struct {
	*cl.CredManager
}

type CLCredManagerContext struct {
	*cl.CredManagerCtx
}

func NewCLCredManagerContext(bytes []byte) (*CLCredManagerContext, error) {
	var ctx cl.CredManagerCtx
	if err := fromBytes(bytes, &ctx); err != nil {
		return nil, err
	}
	return &CLCredManagerContext{
		CredManagerCtx: &ctx,
	}, nil
}

func (c *CLCredManagerContext) Bytes() ([]byte, error) {
	return intoBytes(c.CredManagerCtx)
}

// GetContext returns a CLCredManagerContext filled with
// current state of the CLCredManager. It can be used to restore
// a CLCredManager.
func (cm *CLCredManager) GetContext() *CLCredManagerContext {
	return &CLCredManagerContext{
		CredManagerCtx: &cl.CredManagerCtx{
			Nym:                cm.Nym,
			V1:                 cm.V1,
			CredReqNonce:       cm.CredReqNonce,
			PubKey:             cm.PubKey,
			Params:             cm.Params,
			CommitmentsOfAttrs: cm.CommitmentsOfAttrs,
		},
	}
}

// NewCLCredManager generates credential manager for the CL scheme.
// It accepts parameters for the CL scheme (these must match server-side
// configuration), server's public key, user's secret and attributes to
// manage.
func NewCLCredManager(params *CLParams, pk *CLPubKey,
	secret []byte, cred *CLRawCred) (*CLCredManager,
	error) {

	cm, err := cl.NewCredManager(params.Params,
		pk.PubKey,
		new(big.Int).SetBytes(secret),
		cred.cred)
	if err != nil {
		return nil, err
	}

	return &CLCredManager{
		CredManager: cm,
	}, nil
}

// RestoreCLCredManager establishes credential manager for the CL scheme.
// It is meant to be used to re-establish the credential manager after it
// has been previously created with NewCLCredManager.
func RestoreCLCredManager(ctx *CLCredManagerContext, secret []byte,
	cred *CLRawCred) (*CLCredManager, error) {
	cm, err := cl.RestoreCredManager(
		ctx.CredManagerCtx,
		new(big.Int).SetBytes(secret),
		cred.cred,
	)
	if err != nil {
		return nil, err
	}

	return &CLCredManager{
		CredManager: cm,
	}, nil
}

func (c *CLClient) GetPublicParams() (*CLPublicParams, error) {
	pp, err := c.Client.GetPublicParams()
	if err != nil {
		return nil, err
	}

	return &CLPublicParams{
		PubKey:  &CLPubKey{PubKey: pp.PubKey},
		Config:  &CLParams{Params: pp.Config},
		RawCred: &CLRawCred{cred: pp.RawCred},
	}, nil
}

func (c *CLClient) IssueCred(cm *CLCredManager, regKey string) (*CLCred,
	error) {
	cred, err := c.Client.IssueCredential(cm.CredManager, regKey)
	if err != nil {
		return nil, err
	}

	return &CLCred{
		Cred: cred,
	}, nil
}

// intoBytes takes a struct and attempts to encode it into a
// byte array using go binary encoder.
func intoBytes(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// fromBytes takes bytes and attempts to decode them into
// destination struct using go binary decoder.
func fromBytes(buf []byte, dest interface{}) error {
	data := bytes.NewBuffer(buf)
	dec := gob.NewDecoder(data)
	return dec.Decode(dest)
}