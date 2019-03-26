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

	"github.com/emmyzkp/crypto/schnorr"
	pb "github.com/emmyzkp/emmy/anauth/psys/psyspb"
	"google.golang.org/grpc"
)

type CAClient struct {
	pb.CAClient
	group *schnorr.Group
	//prover *schnorr.Prover // TODO do we need it?
}

func NewCAClient(g *schnorr.Group) *CAClient {
	return &CAClient{
		group: g,
		// prover?
	}
}

func (c *CAClient) Connect(conn *grpc.ClientConn) *CAClient {
	c.CAClient = pb.NewCAClient(conn)
	return c

}

// GenerateMasterNym generates a master pseudonym to be used with GenerateCertificate.
func (c *CAClient) GenerateMasterNym(secret *big.Int) *Nym {
	p := c.group.Exp(c.group.G, secret)
	return NewNym(c.group.G, p)
}

// GenerateCertificate provides a certificate from trusted CA to the user. Note that CA
// needs to know the user. The certificate is then used for registering pseudonym (nym).
// The certificate contains blinded user's master key pair and a signature of it.
func (c *CAClient) GenerateCertificate(userSecret *big.Int, nym *Nym) (
	*CACert, error) {
	if c.CAClient == nil {
		return nil, fmt.Errorf("client is not connected")
	}

	stream, err := c.CAClient.GenerateCertificate(context.Background())
	if err != nil {
		return nil, err
	}

	prover, err := schnorr.NewProver(c.group, []*big.Int{userSecret}, []*big.Int{nym.A}, nym.B)
	if err != nil {
		return nil, err
	}
	//c.prover = prover
	x := prover.GetProofRandomData()
	b := prover.Group.Exp(nym.A, userSecret)

	if err := stream.Send(
		&pb.CARequest{
			Type: &pb.CARequest_ProofRandData{
				ProofRandData: &pb.ProofRandData{
					X: x.Bytes(),
					A: nym.A.Bytes(),
					B: b.Bytes(),
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

	if err := stream.CloseSend(); err != nil {
		return nil, err
	}

	cert := resp.GetCert()
	return NewCACert(
		new(big.Int).SetBytes(cert.BlindedA),
		new(big.Int).SetBytes(cert.BlindedB),
		new(big.Int).SetBytes(cert.R),
		new(big.Int).SetBytes(cert.S)), nil
}
