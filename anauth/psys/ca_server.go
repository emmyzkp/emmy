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
	"math/big"

	"github.com/emmyzkp/crypto/schnorr"
	pb "github.com/emmyzkp/emmy/anauth/psys/psyspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *CAServer) RegisterTo(grpcSrv *grpc.Server) {
	pb.RegisterCAServer(grpcSrv, s)
}

type CAServer struct {
	ca *CA
}

func NewCAServer(group *schnorr.Group, secKey *big.Int, pubKey *PubKey) *CAServer {
	return &CAServer{
		ca: NewCA(group, secKey, pubKey),
	}
}

func (s *CAServer) GenerateCertificate(stream pb.CA_GenerateCertificateServer) error {
	var err error

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	pRandData := req.GetProofRandData()
	x := new(big.Int).SetBytes(pRandData.X)
	a := new(big.Int).SetBytes(pRandData.A)
	b := new(big.Int).SetBytes(pRandData.B)

	ch := s.ca.GetChallenge(a, b, x)
	if err := stream.Send(&pb.CAResponse{
		Type: &pb.CAResponse_Challenge{
			Challenge: ch.Bytes(),
		},
	}); err != nil {
		return err
	}

	req, err = stream.Recv()
	if err != nil {
		return err
	}

	z := new(big.Int).SetBytes(req.GetProofData())
	cert, err := s.ca.Verify(z)
	if err != nil {
		//s.Logger.Debug(err)
		// FIXME don't report err.Error
		return status.Error(codes.Internal, err.Error())
	}

	return stream.Send(
		&pb.CAResponse{
			Type: &pb.CAResponse_Cert{
				Cert: &pb.Cert{
					BlindedA: cert.BlindedA.Bytes(),
					BlindedB: cert.BlindedB.Bytes(),
					R:        cert.R.Bytes(),
					S:        cert.S.Bytes(),
				},
			},
		})
}
