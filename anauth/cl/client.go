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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/emmyzkp/crypto/schnorr"
	"golang.org/x/net/context"

	"github.com/emmyzkp/crypto/pedersen"

	"github.com/emmyzkp/crypto/common"
	"github.com/emmyzkp/crypto/qr"
	pb "github.com/emmyzkp/emmy/anauth/cl/clpb"
	"google.golang.org/grpc"
)

type Client struct {
	pb.AnonCredsClient // TODO fix my name
}

func NewClient(conn *grpc.ClientConn) *Client {
	return &Client{
		AnonCredsClient: pb.NewAnonCredsClient(conn),
	}
}

func (c *Client) GetPublicParams() (*PubParams, error) {
	if c.AnonCredsClient == nil {
		return nil, fmt.Errorf("client is not connected")
	}

	p, err := c.AnonCredsClient.GetPublicParams(context.Background(),
		&pb.Empty{})
	if err != nil {
		return nil, err
	}

	pubKey := &PubKey{
		N:           new(big.Int).SetBytes(p.PubKey.N),
		S:           new(big.Int).SetBytes(p.PubKey.S),
		Z:           new(big.Int).SetBytes(p.PubKey.Z),
		RsKnown:     fromByteSlices(p.PubKey.RsKnown),
		RsCommitted: fromByteSlices(p.PubKey.RsCommitted),
		RsHidden:    fromByteSlices(p.PubKey.RsHidden),
		PedersenParams: pedersen.NewParams(
			schnorr.NewGroupFromParams(
				new(big.Int).SetBytes(p.PubKey.PedersenParams.SchnorrGroup.P),
				new(big.Int).SetBytes(p.PubKey.PedersenParams.SchnorrGroup.G),
				new(big.Int).SetBytes(p.PubKey.PedersenParams.SchnorrGroup.Q),
			),
			new(big.Int).SetBytes(p.PubKey.PedersenParams.H), nil),
		N1: new(big.Int).SetBytes(p.PubKey.N1),
		G:  new(big.Int).SetBytes(p.PubKey.G),
		H:  new(big.Int).SetBytes(p.PubKey.H),
	}

	rc, err := c.parseCredStructure(p.CredStructure)
	if err != nil {
		return nil, err
	}

	return &PubParams{
		PubKey:  pubKey,
		Config:  p.Params,
		RawCred: rc,
	}, nil
}

func (c *Client) parseCredStructure(cs *pb.CredStructure) (*RawCred, error) {
	count := NewAttrCount(
		int(cs.NKnown),
		int(cs.NCommitted),
		int(cs.NHidden),
	)
	rc := NewRawCred(count)

	attrs := cs.Attributes
	for _, a := range attrs {
		switch a.Type.(type) { // TODO make more intuitive
		case *pb.CredAttribute_StringAttr:
			strA := a.GetStringAttr().Attr
			err := rc.addEmptyStrAttr(strA.Name, int(strA.Index), strA.Known)
			if err != nil {
				return nil, err
			}
		case *pb.CredAttribute_IntAttr:
			intA := a.GetIntAttr().Attr
			err := rc.addEmptyInt64Attr(intA.Name, int(intA.Index), intA.Known)
			if err != nil {
				return nil, err
			}
		}
	}

	return rc, nil
}

func (c *Client) GetAcceptableCreds() (map[string][]string, error) {
	if c.AnonCredsClient == nil {
		return nil, fmt.Errorf("client is not connected")
	}

	ac, err := c.AnonCredsClient.GetAcceptableCreds(context.Background(), &pb.Empty{})
	if err != nil {
		return nil, err
	}

	accCreds := make(map[string][]string)
	for _, cred := range ac.Creds {
		var attrs []string
		for _, attr := range cred.RevealedAttrs {
			attrs = append(attrs, attr)
		}
		accCreds[cred.OrgName] = attrs
	}
	return accCreds, nil

}

func (c *Client) IssueCredential(cm *CredManager, regKey string) (*Cred,
	error) {
	if c.AnonCredsClient == nil {
		return nil, fmt.Errorf("client is not connected")
	}

	stream, err := c.AnonCredsClient.Issue(context.Background())
	if err != nil {
		return nil, err
	}

	if err := stream.Send(
		&pb.Request{
			Type: &pb.Request_RegKey{
				RegKey: regKey,
			},
		}); err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	credIssueNonceOrg := new(big.Int).SetBytes(resp.GetNonce())
	credReq, err := cm.GetCredRequest(credIssueNonceOrg)
	if err != nil {
		return nil, err
	}

	pData := toByteSlices(credReq.NymProof.ProofData)
	nymProof := &pb.FiatShamir{
		ProofRandomData: credReq.NymProof.ProofRandomData.Bytes(),
		Challenge:       credReq.NymProof.Challenge.Bytes(),
		ProofData:       pData,
	}

	UProof := &pb.FiatShamirAlsoNeg{
		ProofRandomData: credReq.UProof.ProofRandomData.Bytes(),
		Challenge:       credReq.UProof.Challenge.Bytes(),
		ProofData:       toStringSlices(credReq.UProof.ProofData),
	}

	proofs := make([]*pb.FiatShamir, len(credReq.CommitmentsOfAttrsProofs))
	for i, proof := range credReq.CommitmentsOfAttrsProofs {
		pData = make([][]byte, 2)
		pData[0] = proof.ProofData1.Bytes()
		pData[1] = proof.ProofData2.Bytes()
		fs := &pb.FiatShamir{
			ProofRandomData: proof.ProofRandomData.Bytes(),
			Challenge:       proof.Challenge.Bytes(),
			ProofData:       pData,
		}
		proofs[i] = fs
	}

	if err := stream.Send(
		&pb.Request{
			Type: &pb.Request_CredIssue{
				CredIssue: &pb.CredIssueRequest{
					Nym:                credReq.Nym.Bytes(),
					KnownAttrs:         toByteSlices(credReq.KnownAttrs),
					CommitmentsOfAttrs: toByteSlices(credReq.CommitmentsOfAttrs),
					NymProof:           nymProof,
					U:                  credReq.U.Bytes(),
					UProof:             UProof,
					CommitmentsOfAttrsProofs: proofs,
					Nonce: credReq.Nonce.Bytes(),
				},
			},
		}); err != nil {
		return nil, err
	}

	resp, err = stream.Recv()
	if err != nil {
		return nil, err
	}

	issuedCred := resp.GetIssuedCred()

	si, success := new(big.Int).SetString(issuedCred.AProof.ProofData[0], 10)
	if !success {
		return nil, fmt.Errorf("error when initializing big.Int from string")
	}

	cred := NewCred(
		new(big.Int).SetBytes(issuedCred.Cred.A),
		new(big.Int).SetBytes(issuedCred.Cred.E),
		new(big.Int).SetBytes(issuedCred.Cred.V11),
	)
	AProof := qr.NewRepresentationProof(
		new(big.Int).SetBytes(issuedCred.AProof.ProofRandomData),
		new(big.Int).SetBytes(issuedCred.AProof.Challenge),
		[]*big.Int{si},
	)

	if err != nil {
		return nil, err
	}

	userVerified, err := cm.Verify(cred, AProof)
	if err != nil {
		return nil, err
	}

	if userVerified {
		return cred, nil
	}

	if err := stream.CloseSend(); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("credential not valid")
}

func (c *Client) UpdateCredential(cm *CredManager, rawCred *RawCred) (*Cred,
	error) {
	if c.AnonCredsClient == nil {
		return nil, fmt.Errorf("client is not connected")
	}

	// refresh credManager with new credential values,
	// works only for Known attributes
	cm.Update(rawCred)
	newKnownAttrs := rawCred.GetKnownVals()

	req := &pb.CredUpdateRequest{
		Nym:           cm.Nym.Bytes(),
		Nonce:         cm.CredReqNonce.Bytes(),
		NewKnownAttrs: toByteSlices(newKnownAttrs),
	}

	updatedCred, err := c.AnonCredsClient.Update(context.Background(), req)
	if err != nil {
		return nil, err
	}

	si, success := new(big.Int).SetString(updatedCred.AProof.ProofData[0], 10)
	if !success {
		return nil, fmt.Errorf("error when initializing big.Int from string")
	}

	cred := NewCred(
		new(big.Int).SetBytes(updatedCred.Cred.A),
		new(big.Int).SetBytes(updatedCred.Cred.E),
		new(big.Int).SetBytes(updatedCred.Cred.V11),
	)
	AProof := qr.NewRepresentationProof(
		new(big.Int).SetBytes(updatedCred.AProof.ProofRandomData),
		new(big.Int).SetBytes(updatedCred.AProof.Challenge),
		[]*big.Int{si},
	)

	userVerified, err := cm.Verify(cred, AProof)
	if err != nil {
		return nil, err
	}

	if userVerified {
		return cred, nil
	}

	return nil, fmt.Errorf("cred not valid")
}

// ProveCred proves the possession of a valid credential and reveals only the attributes the user desires
// to reveal. Which knownAttrs and commitmentsOfAttrs are to be revealed are given by revealedKnownAttrsIndices and
// revealedCommitmentsOfAttrsIndices parameters. All knownAttrs and commitmentsOfAttrs should be passed into
// ProveCred - only those which are revealed are then passed to the server.
func (c *Client) ProveCredential(cm *CredManager, cred *Cred,
	revealedAttrs []string) (*string, error) {
	if c.AnonCredsClient == nil {
		return nil, fmt.Errorf("client is not connected")
	}

	var revealedKnownAttrsIndices []int
	var revealedCommitmentsOfAttrsIndices []int
	knownCount := 0
	commCount := 0

	for _, a := range revealedAttrs {
		attr, err := cm.RawCred.GetAttr(a)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"unexpected attribute: %s", a)
		}

		if attr.isKnown() {
			revealedKnownAttrsIndices = append(revealedKnownAttrsIndices, knownCount)
			knownCount++
		} else {
			revealedCommitmentsOfAttrsIndices = append(revealedCommitmentsOfAttrsIndices, commCount)
			commCount++
		}
	}

	stream, err := c.AnonCredsClient.Prove(context.Background())
	if err != nil {
		return nil, err
	}

	if err := stream.Send(emptyRequest()); err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	nonce := new(big.Int).SetBytes(resp.GetNonce())

	randCred, proof, err := cm.BuildProof(cred, revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices, nonce)
	if err != nil {
		return nil, fmt.Errorf("error when building credential proof: %v", err)
	}

	filteredKnownAttrs, filteredCommitmentsOfAttrs := cm.FilterAttributes(
		revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices)

	// TODO disappeared?
	revealedKnownAttrs := make([]int32, len(revealedKnownAttrsIndices))
	for i, a := range revealedKnownAttrsIndices {
		revealedKnownAttrs[i] = int32(a)
	}

	// TODO disappeared?
	revealedCommitmentsOfAttrs := make([]int32, len(revealedCommitmentsOfAttrsIndices))
	for i, a := range revealedCommitmentsOfAttrsIndices {
		revealedCommitmentsOfAttrs[i] = int32(a)
	}

	proveMsg := &pb.Request{
		Type: &pb.Request_CredProve{
			CredProve: &pb.CredProof{
				A: randCred.A.Bytes(),
				Proof: &pb.FiatShamirAlsoNeg{
					ProofRandomData: proof.ProofRandomData.Bytes(),
					Challenge:       proof.Challenge.Bytes(),
					ProofData:       toStringSlices(proof.ProofData),
				},
				KnownAttrs:                 toByteSlices(filteredKnownAttrs),
				CommitmentsOfAttrs:         toByteSlices(filteredCommitmentsOfAttrs),
				RevealedKnownAttrs:         revealedKnownAttrs,
				RevealedCommitmentsOfAttrs: revealedCommitmentsOfAttrs,
			},
		},
	}

	if err := stream.Send(proveMsg); err != nil {
		return nil, err
	}

	resp, err = stream.Recv()
	if err != nil {
		return nil, err
	}

	if err := stream.CloseSend(); err != nil {
		return nil, err
	}

	sessKey := resp.GetSessionKey()

	return &sessKey, nil
}

func emptyRequest() *pb.Request {
	return &pb.Request{
		Type: &pb.Request_Empty{
			Empty: &pb.Empty{},
		},
	}
}

func filterSlice(s []*big.Int, revealed []int) []*big.Int {
	var res []*big.Int
	for i := 0; i < len(s); i++ {
		if common.Contains(revealed, i) {
			res = append(res, s[i])
		}
	}

	return res
}

func toByteSlices(s []*big.Int) [][]byte {
	res := make([][]byte, len(s))
	for i, si := range s {
		res[i] = si.Bytes()
	}

	return res
}

func toStringSlices(s []*big.Int) []string {
	res := make([]string, len(s))
	for i, p := range s {
		res[i] = p.String()
	}

	return res
}
