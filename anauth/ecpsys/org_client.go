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

package ecpsys

import (
	"fmt"
	"math/big"

	"context"

	"github.com/emmyzkp/crypto/common"
	"github.com/emmyzkp/crypto/ec"
	"github.com/emmyzkp/crypto/ecschnorr"
	pb "github.com/emmyzkp/emmy/anauth/ecpsys/ecpsyspb"
	"github.com/emmyzkp/emmy/anauth/psys/psyspb"
	"google.golang.org/grpc"
)

type Client struct {
	pb.Org_ECClient
	curve ec.Curve
}

func NewClient(conn *grpc.ClientConn, curve ec.Curve) (*Client, error) {
	return &Client{
		Org_ECClient: pb.NewOrg_ECClient(conn),
		curve:        curve,
	}, nil
}

// TODO make it without connection ?
// GenerateMasterKey generates a master secret key to be used subsequently by all the
// protocols in the scheme.
func (c *Client) GenerateMasterKey() *big.Int {
	group := ec.NewGroup(c.curve)
	return common.GetRandomInt(group.Q)
}

// GenerateNym generates a nym and registers it to the organization. Do not
// use the same CACert for different organizations - use it only once!
func (c *Client) GenerateNym(userSecret *big.Int, caCert *CACert,
	regKey string) (*Nym, error) {
	stream, err := c.Org_ECClient.GenerateNym(context.Background())
	if err != nil {
		return nil, err
	}

	prover := ecschnorr.NewEqualityProver(c.curve)

	// Differently as in Pseudonym Systems paper a user here generates a nym (if master
	// key pair is (g, g^s), a generated nym is (g^gamma, g^(gamma * s)),
	// however a user needs to prove that log_nymA(nymB) = log_blindedA(blindedB).

	// Note that as there is very little logic needed (besides what is in DLog equality
	// prover), everything is implemented here (no pseudoynymsys nym gen client).

	masterNymA := ec.NewGroupElement(
		prover.Group.Curve.Params().Gx,
		prover.Group.Curve.Params().Gy,
	)
	masterNymB := prover.Group.Exp(masterNymA, userSecret)

	gamma := common.GetRandomInt(prover.Group.Q)
	nymA := prover.Group.Exp(masterNymA, gamma)
	nymB := prover.Group.Exp(masterNymB, gamma)

	// Prove now that log_nymA(nymB) = log_blindedA(blindedB):
	// g1 = nymA, g2 = blindedA
	x1, x2 := prover.GetProofRandomData(userSecret, nymA, caCert.BlindedA)

	if err := stream.Send(
		&pb.GenerateNymRequest{
			Type: &pb.GenerateNymRequest_ProofRandData{
				ProofRandData: &pb.GenerateNymProofRandData{
					X1:     toPbECGroupElement(x1),
					A1:     toPbECGroupElement(nymA),
					B1:     toPbECGroupElement(nymB),
					X2:     toPbECGroupElement(x2),
					A2:     toPbECGroupElement(caCert.BlindedA),
					B2:     toPbECGroupElement(caCert.BlindedB),
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

	decommitment := resp.GetDecommitment()
	challenge := new(big.Int).SetBytes(decommitment.X)
	z := prover.GetProofData(challenge)

	if err := stream.Send(
		&pb.GenerateNymRequest{
			Type: &pb.GenerateNymRequest_ProofData{
				ProofData: z.Bytes(),
			},
		}); err != nil {
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

	// TODO: store in some DB: (orgName, nymA, nymB)
	return NewNym(nymA, nymB), nil
}

// ObtainCredential returns anonymous credential.
func (c *Client) ObtainCredential(userSecret *big.Int,
	nym *Nym, orgPubKeys *PubKey) (
	*Cred, error) {
	stream, err := c.Org_ECClient.ObtainCred(context.Background())
	if err != nil {
		return nil, err
	}

	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. Authentication is done via Schnorr.
	prover := ecschnorr.NewProver(c.curve)

	x := prover.GetProofRandomData(userSecret, nym.A)

	if err := stream.Send(
		&pb.ObtainCredRequest{
			Type: &pb.ObtainCredRequest_ProofRandData{
				ProofRandData: &pb.ProofRandData{
					X: toPbECGroupElement(x),
					A: toPbECGroupElement(nym.A),
					B: toPbECGroupElement(nym.B),
				},
			},
		}); err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	ch := new(big.Int).SetBytes(resp.GetChallenge())
	z := prover.GetProofData(ch)
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

	gamma := common.GetRandomInt(prover.Group.Q)
	verifier1 := ecschnorr.NewBTEqualityVerifier(c.curve, gamma)
	verifier2 := ecschnorr.NewBTEqualityVerifier(c.curve, gamma)

	g := ec.NewGroupElement(
		verifier1.Group.Curve.Params().Gx,
		verifier1.Group.Curve.Params().Gy,
	)

	A := toECGroupElement(randData.A)
	x11 := toECGroupElement(randData.X11)
	x12 := toECGroupElement(randData.X12)
	ch1 := verifier1.GetChallenge(g, nym.B, orgPubKeys.H2, A, x11, x12)
	aA := verifier1.Group.Mul(nym.A, A)

	B := toECGroupElement(randData.B)
	x21 := toECGroupElement(randData.X21)
	x22 := toECGroupElement(randData.X22)
	ch2 := verifier2.GetChallenge(g, aA, orgPubKeys.H1, B, x21, x22)

	if err := stream.Send(
		&pb.ObtainCredRequest{
			Type: &pb.ObtainCredRequest_Challenge{
				Challenge: &psyspb.BytesPair{
					X: ch1.Bytes(),
					Y: ch2.Bytes(),
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

	pData := resp.GetProofData()
	z1 := new(big.Int).SetBytes(pData.X)
	z2 := new(big.Int).SetBytes(pData.Y)

	verified1, t1, bToG, AToG := verifier1.Verify(z1)
	verified2, t2, aAToG, BToG := verifier2.Verify(z2)
	if !verified1 || !verified2 {
		return nil, fmt.Errorf("organization failed to prove that a credential is valid")
	}

	verified1 = t1.Verify(c.curve, g, orgPubKeys.H2, bToG, AToG)
	verified1 = t2.Verify(c.curve, g, orgPubKeys.H1, aAToG, BToG)
	if !verified1 || !verified2 {
		return nil, fmt.Errorf("organization failed to prove that a credential is valid")
	}

	aToG := verifier1.Group.Exp(nym.A, gamma)

	return NewCred(aToG, bToG, AToG, BToG, t1, t2), nil
}

// TransferCredential transfers orgName's credential to organization where the
// authentication should happen (the organization takes credential issued by
// another organization).
func (c *Client) TransferCredential(orgName string, userSecret *big.Int,
	nym *Nym, cred *Cred) (*string, error) {
	stream, err := c.Org_ECClient.TransferCred(context.Background())
	if err != nil {
		return nil, err
	}

	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. But we need also to prove that dlog_a(b) = dlog_a2(b2), where
	// a2, b2 are a1, b1 exponentiated to gamma, and (a1, b1) is a nym for organization that
	// issued a cred. So we can do both proofs at the same time using DLogEqualityProver.
	prover := ecschnorr.NewEqualityProver(c.curve)
	x1, x2 := prover.GetProofRandomData(userSecret, nym.A, cred.SmallAToGamma)

	t1 := &pb.Transcript{
		A:      toPbECGroupElement(ec.NewGroupElement(cred.T1.Alpha_1, cred.T1.Alpha_2)), // TODO!!!
		B:      toPbECGroupElement(ec.NewGroupElement(cred.T1.Beta_1, cred.T1.Beta_2)),
		Hash:   cred.T1.Hash.Bytes(),
		ZAlpha: cred.T1.ZAlpha.Bytes(),
	}
	t2 := &pb.Transcript{
		A:      toPbECGroupElement(ec.NewGroupElement(cred.T2.Alpha_1, cred.T2.Alpha_2)),
		B:      toPbECGroupElement(ec.NewGroupElement(cred.T2.Beta_1, cred.T2.Beta_2)),
		Hash:   cred.T2.Hash.Bytes(),
		ZAlpha: cred.T2.ZAlpha.Bytes(),
	}

	if err := stream.Send(
		&pb.TransferCredRequest{
			Type: &pb.TransferCredRequest_ProofRandData{
				ProofRandData: &pb.TransferCredProofRandData{
					OrgName: orgName,
					X1:      toPbECGroupElement(x1),
					X2:      toPbECGroupElement(x2),
					NymA:    toPbECGroupElement(nym.A),
					NymB:    toPbECGroupElement(nym.B),
					Cred: &pb.Cred{
						SmallAToGamma: toPbECGroupElement(cred.SmallAToGamma),
						SmallBToGamma: toPbECGroupElement(cred.SmallBToGamma),
						AToGamma:      toPbECGroupElement(cred.AToGamma),
						BToGamma:      toPbECGroupElement(cred.BToGamma),
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

	ch := new(big.Int).SetBytes(resp.GetChallenge())
	z := prover.GetProofData(ch)
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

	sessionKey := resp.GetSessionKey()

	return &sessionKey, nil
}
