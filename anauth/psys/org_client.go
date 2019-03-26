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

package psys

import (
	"fmt"
	"math/big"

	"context"

	"github.com/emmyzkp/crypto/common"
	"github.com/emmyzkp/crypto/schnorr"
	pb "github.com/emmyzkp/emmy/anauth/psys/psyspb"
	"google.golang.org/grpc"
)

type Client struct {
	pb.OrgClient
	group *schnorr.Group
}

func NewClient(conn *grpc.ClientConn, group *schnorr.Group) (*Client, error) {
	return &Client{
		group:     group,
		OrgClient: pb.NewOrgClient(conn),
	}, nil
}

// GenerateMasterKey generates a master secret key, representing a random integer betweeen
// 0 and order of the group. This key will be used subsequently by all the protocols in the scheme.
func (c *Client) GenerateMasterKey() *big.Int {
	return common.GetRandomInt(c.group.Q)
}

// GenerateNym generates a nym and registers it to the organization. Do not use
// the same CACert for different organizations - use it only once!
func (c *Client) GenerateNym(userSecret *big.Int,
	caCert *CACert, regKey string) (
	*Nym, error) {
	stream, err := c.OrgClient.GenerateNym(context.Background())
	if err != nil {
		return nil, err
	}

	prover := schnorr.NewEqualityProver(c.group)

	// Differently as in Pseudonym Systems paper a user here generates a nym (if master
	// key pair is (g, g^s), a generated nym is (g^gamma, g^(gamma * s)),
	// however a user needs to prove that log_nymA(nymB) = log_blindedA(blindedB).

	// Note that as there is very little logic needed (besides what is in DLog equality
	// prover), everything is implemented here (no pseudoynymsys nym gen client).
	gamma := common.GetRandomInt(prover.Group.Q)
	nymA := c.group.Exp(c.group.G, gamma)
	nymB := c.group.Exp(nymA, userSecret)

	// Prove now that log_nymA(nymB) = log_blindedA(blindedB):
	// g1 = nymA, g2 = blindedA
	x1, x2 := prover.GetProofRandomData(userSecret, nymA, caCert.BlindedA)

	if err := stream.Send(
		&pb.GenerateNymRequest{
			Type: &pb.GenerateNymRequest_ProofRandData{
				ProofRandData: &pb.GenerateNymProofRandData{
					X1:     x1.Bytes(),
					A1:     nymA.Bytes(),
					B1:     nymB.Bytes(),
					X2:     x2.Bytes(),
					A2:     caCert.BlindedA.Bytes(),
					B2:     caCert.BlindedB.Bytes(),
					R:      caCert.R.Bytes(),
					S:      caCert.S.Bytes(),
					RegKey: regKey,
				},
			},
		}); err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	ch := new(big.Int).SetBytes(resp.GetDecommitment().X)
	z := prover.GetProofData(ch)

	if err := stream.Send(
		&pb.GenerateNymRequest{
			Type: &pb.GenerateNymRequest_ProofData{
				ProofData: z.Bytes(),
			},
		}); err != nil {
		return nil, err
	}

	resp, err = stream.Recv()
	if err != nil {
		return nil, err
	}

	if err := stream.CloseSend(); err != nil {
		return nil, err
	}

	if !resp.GetSuccess() {
		return nil, fmt.Errorf("proof for nym registration failed")
	}

	// todo: store in some DB: (orgName, nymA, nymB)
	return NewNym(nymA, nymB), nil
}

// ObtainCredential returns anonymous credential.
func (c *Client) ObtainCredential(userSecret *big.Int,
	nym *Nym, orgPubKeys *PubKey) (*Cred, error) {
	stream, err := c.OrgClient.ObtainCred(context.Background())
	if err != nil {
		return nil, err
	}

	gamma := common.GetRandomInt(c.group.Q)
	verifier1 := schnorr.NewBTEqualityVerifier(c.group, gamma)
	verifier2 := schnorr.NewBTEqualityVerifier(c.group, gamma)

	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. Authentication is done via Schnorr.
	prover, err := schnorr.NewProver(c.group, []*big.Int{userSecret}, []*big.Int{nym.A}, nym.B)
	if err != nil {
		return nil, err
	}

	x := prover.GetProofRandomData()

	if err := stream.Send(
		&pb.ObtainCredRequest{
			Type: &pb.ObtainCredRequest_ProofRandData{
				ProofRandData: &pb.ProofRandData{
					X: x.Bytes(),
					A: nym.A.Bytes(),
					B: nym.B.Bytes(),
				},
			},
		}); err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	challenge := new(big.Int).SetBytes(resp.GetChallenge())
	z := prover.GetProofData(challenge)[0]

	if err := stream.Send(
		&pb.ObtainCredRequest{
			Type: &pb.ObtainCredRequest_ProofData{
				ProofData: z.Bytes(),
			},
		}); err != nil {
		return nil, err
	}

	resp, err = stream.Recv()
	if err != nil {
		return nil, err
	}

	randData := resp.GetProofRandData()
	// Now the organization needs to prove that it knows log_b(A), log_g(h2) and log_b(A) = log_g(h2).
	// And to prove that it knows log_aA(B), log_g(h1) and log_aA(B) = log_g(h1).
	// g1 = dlog.G, g2 = nym.B, t1 = A, t2 = orgPubKeys.H2

	x11 := new(big.Int).SetBytes(randData.X11)
	x12 := new(big.Int).SetBytes(randData.X12)
	x21 := new(big.Int).SetBytes(randData.X21)
	x22 := new(big.Int).SetBytes(randData.X22)
	A := new(big.Int).SetBytes(randData.A)
	B := new(big.Int).SetBytes(randData.B)

	challenge1 := verifier1.GetChallenge(c.group.G, nym.B, orgPubKeys.H2, A, x11, x12)
	aA := c.group.Mul(nym.A, A)
	challenge2 := verifier2.GetChallenge(c.group.G, aA, orgPubKeys.H1, B, x21, x22)

	if err := stream.Send(
		&pb.ObtainCredRequest{
			Type: &pb.ObtainCredRequest_Challenge{
				Challenge: &pb.BytesPair{
					X: challenge1.Bytes(),
					Y: challenge2.Bytes(),
				},
			},
		}); err != nil {
		return nil, err
	}

	resp, err = stream.Recv()
	if err != nil {
		return nil, err
	}

	if err := stream.CloseSend(); err != nil {
		return nil, err
	}

	proofData := resp.GetProofData()
	z1 := new(big.Int).SetBytes(proofData.X)
	z2 := new(big.Int).SetBytes(proofData.Y)

	verified1, transcript1, bToGamma, AToGamma := verifier1.Verify(z1)
	verified2, transcript2, aAToGamma, BToGamma := verifier2.Verify(z2)

	aToGamma := c.group.Exp(nym.A, gamma)
	if verified1 && verified2 {
		valid1 := transcript1.Verify(c.group, c.group.G, orgPubKeys.H2,
			bToGamma, AToGamma)
		valid2 := transcript2.Verify(c.group, c.group.G, orgPubKeys.H1,
			aAToGamma, BToGamma)
		if valid1 && valid2 {
			credential := NewCred(aToGamma, bToGamma, AToGamma, BToGamma,
				transcript1, transcript2)
			return credential, nil
		}
	}

	err = fmt.Errorf("organization failed to prove that a credential is valid")
	return nil, err
}

// FIXME get rid of orgname?
// TransferCredential transfers orgName's credential to organization where the
// authentication should happen (the organization takes credential issued by
// another organization).
func (c *Client) TransferCredential(orgName string, userSecret *big.Int,
	nym *Nym, cred *Cred) (*string, error) {
	stream, err := c.OrgClient.TransferCred(context.Background())
	if err != nil {
		return nil, err
	}

	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. But we need also to prove that dlog_a(b) = dlog_a2(b2), where
	// a2, b2 are a1, b1 exponentiated to gamma, and (a1, b1) is a nym for organization that
	// issued a cred. So we can do both proofs at the same time using EqualityProver.
	prover := schnorr.NewEqualityProver(c.group)
	x1, x2 := prover.GetProofRandomData(userSecret, nym.A, cred.SmallAToGamma)

	t1 := &pb.Transcript{
		A:      cred.T1.A.Bytes(),
		B:      cred.T1.B.Bytes(),
		Hash:   cred.T1.Hash.Bytes(),
		ZAlpha: cred.T1.ZAlpha.Bytes(),
	}
	t2 := &pb.Transcript{
		A:      cred.T2.A.Bytes(),
		B:      cred.T2.B.Bytes(),
		Hash:   cred.T2.Hash.Bytes(),
		ZAlpha: cred.T2.ZAlpha.Bytes(),
	}

	if err := stream.Send(
		&pb.TransferCredRequest{
			Type: &pb.TransferCredRequest_ProofRandData{
				ProofRandData: &pb.TransferCredProofRandData{
					X1:   x1.Bytes(),
					X2:   x2.Bytes(),
					NymA: nym.A.Bytes(),
					NymB: nym.B.Bytes(),
					Cred: &pb.Cred{
						SmallAToGamma: cred.SmallAToGamma.Bytes(),
						SmallBToGamma: cred.SmallBToGamma.Bytes(),
						AToGamma:      cred.AToGamma.Bytes(),
						BToGamma:      cred.BToGamma.Bytes(),
						T1:            t1,
						T2:            t2,
					},
				},
			},
		}); err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	challenge := new(big.Int).SetBytes(resp.GetChallenge())

	z := prover.GetProofData(challenge)
	if err := stream.Send(
		&pb.TransferCredRequest{
			Type: &pb.TransferCredRequest_ProofData{
				ProofData: z.Bytes(),
			},
		}); err != nil {
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
