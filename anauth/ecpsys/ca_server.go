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
	"math/big"

	"github.com/emmyzkp/crypto/ec"
	pb "github.com/emmyzkp/emmy/anauth/ecpsys/ecpsyspb"
	"github.com/emmyzkp/emmy/anauth/psys"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *CAServer) RegisterTo(grpcSrv *grpc.Server) {
	pb.RegisterCA_ECServer(grpcSrv, s)
}

type CAServer struct {
	ca *CA
}

func NewCAServer(secKey *big.Int, pubKey *psys.PubKey, curve ec.Curve) *CAServer {
	return &CAServer{
		ca: NewCA(secKey, pubKey, curve),
	}
}

func (s *CAServer) GenerateCertificate(stream pb.
	CA_EC_GenerateCertificateServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	pRandData := req.GetProofRandData()
	ch := s.ca.GetChallenge(
		toECGroupElement(pRandData.A),
		toECGroupElement(pRandData.B),
		toECGroupElement(pRandData.X),
	)

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
		return status.Error(codes.Internal, err.Error())
	}

	return stream.Send(&pb.CAResponse{
		Type: &pb.CAResponse_Cert{
			Cert: &pb.Cert{
				BlindedA: &pb.ECGroupElement{
					X: cert.BlindedA.X.Bytes(),
					Y: cert.BlindedA.Y.Bytes(),
				},
				BlindedB: &pb.ECGroupElement{
					X: cert.BlindedB.X.Bytes(),
					Y: cert.BlindedB.Y.Bytes(),
				},
				R: cert.R.Bytes(),
				S: cert.S.Bytes(),
			},
		},
	})
}

func toECGroupElement(el *pb.ECGroupElement) *ec.GroupElement {
	return &ec.GroupElement{
		X: new(big.Int).SetBytes(el.X),
		Y: new(big.Int).SetBytes(el.Y),
	}
}
