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
	"github.com/emmyzkp/emmy/anauth"
	pb "github.com/emmyzkp/emmy/anauth/psys/psyspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type OrgServer struct {
	pubKey *PubKey

	*NymGenerator
	*CredIssuer
	*CredVerifier

	SessMgr anauth.SessManager
	RegMgr  anauth.RegManager
}

func NewOrgServer(group *schnorr.Group, secKey *SecKey, pubKey, caPubKey *PubKey) *OrgServer {
	return &OrgServer{
		pubKey:       pubKey,
		NymGenerator: NewNymGenerator(group, caPubKey),
		CredIssuer:   NewCredIssuer(group, secKey),
		CredVerifier: NewCredVerifier(group, secKey),
	}
}

func (s *OrgServer) RegisterTo(grpcSrv *grpc.Server) {
	pb.RegisterOrgServer(grpcSrv, s)
}

func (s *OrgServer) GenerateNym(stream pb.Org_GenerateNymServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	proofRandData := req.GetProofRandData()
	x1 := new(big.Int).SetBytes(proofRandData.X1)
	nymA := new(big.Int).SetBytes(proofRandData.A1)
	nymB := new(big.Int).SetBytes(proofRandData.B1)
	x2 := new(big.Int).SetBytes(proofRandData.X2)
	blindedA := new(big.Int).SetBytes(proofRandData.A2)
	blindedB := new(big.Int).SetBytes(proofRandData.B2)
	signatureR := new(big.Int).SetBytes(proofRandData.R)
	signatureS := new(big.Int).SetBytes(proofRandData.S)

	regKeyOk, err := s.RegMgr.CheckRegistrationKey(proofRandData.RegKey)

	if !regKeyOk || err != nil {
		//s.Logger.Debugf("registration key %s ok=%t, error=%v",
		//	proofRandData.RegKey, regKeyOk, err)
		return status.Error(codes.NotFound, "registration key verification failed")
	}

	ch, err := s.NymGenerator.GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2, signatureR, signatureS)
	if err != nil {
		//s.Logger.Debug(err)
		return status.Error(codes.Internal, err.Error())

	}
	if err := stream.Send(
		&pb.GenerateNymResponse{
			Type: &pb.GenerateNymResponse_Decommitment{ // Rename decommitment to ch?
				Decommitment: &pb.PedersenDecommitment{
					X: ch.Bytes(), // TODO what about R?????
				},
			},
		}); err != nil {
		return err
	}

	req, err = stream.Recv()
	if err != nil {
		return err
	}

	// SchnorrProofData is used in DLog equality proof as well
	z := new(big.Int).SetBytes(req.GetProofData())
	valid := s.NymGenerator.Verify(z)

	return stream.Send(
		&pb.GenerateNymResponse{
			Type: &pb.GenerateNymResponse_Success{
				Success: valid,
			},
		})
}

func (s *OrgServer) ObtainCred(stream pb.Org_ObtainCredServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	sProofRandData := req.GetProofRandData()
	x := new(big.Int).SetBytes(sProofRandData.X)
	a := new(big.Int).SetBytes(sProofRandData.A)
	b := new(big.Int).SetBytes(sProofRandData.B)
	ch := s.CredIssuer.GetChallenge(a, b, x)

	if err := stream.Send(
		&pb.ObtainCredResponse{
			Type: &pb.ObtainCredResponse_Challenge{
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

	x11, x12, x21, x22, A, B, err := s.CredIssuer.Verify(z)
	if err != nil {
		//s.Logger.Debug(err)
		return status.Error(codes.Internal, err.Error())
	}
	if err := stream.Send(
		&pb.ObtainCredResponse{
			Type: &pb.ObtainCredResponse_ProofRandData{
				ProofRandData: &pb.ObtainCredProofRandData{
					X11: x11.Bytes(),
					X12: x12.Bytes(),
					X21: x21.Bytes(),
					X22: x22.Bytes(),
					A:   A.Bytes(),
					B:   B.Bytes(),
				},
			},
		}); err != nil {
		return err
	}

	req, err = stream.Recv()
	if err != nil {
		return err
	}

	chPair := req.GetChallenge()
	ch1 := new(big.Int).SetBytes(chPair.X)
	ch2 := new(big.Int).SetBytes(chPair.Y)

	z1, z2 := s.CredIssuer.GetProofData(ch1, ch2)

	return stream.Send(
		&pb.ObtainCredResponse{
			Type: &pb.ObtainCredResponse_ProofData{
				ProofData: &pb.BytesPair{
					X: z1.Bytes(),
					Y: z2.Bytes(),
				},
			},
		})
}

func (s *OrgServer) TransferCred(stream pb.Org_TransferCredServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	data := req.GetProofRandData()

	t1 := schnorr.NewBlindedTrans(
		new(big.Int).SetBytes(data.Cred.T1.A),
		new(big.Int).SetBytes(data.Cred.T1.B),
		new(big.Int).SetBytes(data.Cred.T1.Hash),
		new(big.Int).SetBytes(data.Cred.T1.ZAlpha),
	)
	t2 := schnorr.NewBlindedTrans(
		new(big.Int).SetBytes(data.Cred.T2.A),
		new(big.Int).SetBytes(data.Cred.T2.B),
		new(big.Int).SetBytes(data.Cred.T2.Hash),
		new(big.Int).SetBytes(data.Cred.T2.ZAlpha),
	)
	cred := NewCred(
		new(big.Int).SetBytes(data.Cred.SmallAToGamma),
		new(big.Int).SetBytes(data.Cred.SmallBToGamma),
		new(big.Int).SetBytes(data.Cred.AToGamma),
		new(big.Int).SetBytes(data.Cred.BToGamma),
		t1, t2,
	)

	challenge := s.CredVerifier.GetChallenge(
		new(big.Int).SetBytes(data.NymA),
		new(big.Int).SetBytes(data.NymB),
		cred.SmallAToGamma,
		cred.SmallBToGamma,
		new(big.Int).SetBytes(data.X1),
		new(big.Int).SetBytes(data.X2),
	)

	if err := stream.Send(
		&pb.TransferCredResponse{
			Type: &pb.TransferCredResponse_Challenge{
				Challenge: challenge.Bytes(),
			},
		}); err != nil {
		return err
	}

	req, err = stream.Recv()
	if err != nil {
		return err
	}

	// PubKeys of the organization that issue a cred:
	// FIXME
	z := new(big.Int).SetBytes(req.GetProofData())

	if verified := s.CredVerifier.Verify(z, cred, s.pubKey); !verified {
		//s.Logger.Debug("User authentication failed")
		return status.Error(codes.Unauthenticated, "user authentication failed")
	}

	sessKey, err := s.SessMgr.GenerateSessionKey()
	if err != nil {
		//s.Logger.Debug(err)
		return status.Error(codes.Internal, "failed to obtain session key")
	}

	return stream.Send(
		&pb.TransferCredResponse{
			Type: &pb.TransferCredResponse_SessionKey{
				SessionKey: *sessKey,
			},
		})
}
