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

	"github.com/emmyzkp/crypto/ec"
	"github.com/emmyzkp/crypto/ecschnorr"
	pb "github.com/emmyzkp/emmy/anauth/ecpsys/ecpsyspb"
	"google.golang.org/grpc"
)

type CAClient struct {
	pb.CA_ECClient
	curve  ec.Curve
	prover *ecschnorr.Prover
}

func NewCAClient(curve ec.Curve) *CAClient {
	return &CAClient{
		curve:  curve,
		prover: ecschnorr.NewProver(curve),
	}
}

func (c *CAClient) Connect(conn *grpc.ClientConn) *CAClient {
	c.CA_ECClient = pb.NewCA_ECClient(conn)
	return c
}

// GenerateMasterNym generates a master pseudonym to be used with GenerateCertificate.
func (c *CAClient) GenerateMasterNym(secret *big.Int) *Nym {
	group := ec.NewGroup(c.curve)
	a := ec.NewGroupElement(group.Curve.Params().Gx, group.Curve.Params().Gy)
	b := group.Exp(a, secret)
	return NewNym(a, b)
}

// GenerateCertificate provides a certificate from trusted CA to the user. Note that CA
// needs to know the user. The certificate is then used for registering pseudonym (nym).
// The certificate contains blinded user's master key pair and a signature of it.
func (c *CAClient) GenerateCertificate(userSecret *big.Int, nym *Nym) (*CACert, error) {
	if c.CA_ECClient == nil {
		return nil, fmt.Errorf("client is not connected")
	}

	stream, err := c.CA_ECClient.GenerateCertificate(context.Background())
	if err != nil {
		return nil, err
	}

	x := c.prover.GetProofRandomData(userSecret, nym.A)

	if err := stream.Send(&pb.CARequest{
		Type: &pb.CARequest_ProofRandData{
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
	z := c.prover.GetProofData(ch)

	if err := stream.Send(&pb.CARequest{
		Type: &pb.CARequest_ProofData{
			ProofData: z.Bytes(),
		},
	}); err != nil {
		return nil, err
	}

	resp, err = stream.Recv()
	if err != nil {
		return nil, err
	}

	// TODO does it affect recv?
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}

	cert := resp.GetCert()
	return NewCACert(
		toECGroupElement(cert.BlindedA),
		toECGroupElement(cert.BlindedB),
		new(big.Int).SetBytes(cert.R),
		new(big.Int).SetBytes(cert.S)), nil
}

func toPbECGroupElement(el *ec.GroupElement) *pb.ECGroupElement {
	return &pb.ECGroupElement{
		X: el.X.Bytes(),
		Y: el.Y.Bytes(),
	}
}
