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
	"github.com/emmyzkp/crypto/ecschnorr"
	"github.com/emmyzkp/emmy/anauth"
	pb "github.com/emmyzkp/emmy/anauth/ecpsys/ecpsyspb"
	"github.com/emmyzkp/emmy/anauth/psys"
	"github.com/emmyzkp/emmy/anauth/psys/psyspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *OrgServer) RegisterTo(grpcSrv *grpc.Server) {
	pb.RegisterOrg_ECServer(grpcSrv, s)
}

type OrgServer struct {
	pubKey *PubKey

	*NymGenerator
	*CredIssuer
	*CredVerifier

	SessMgr anauth.SessManager
	RegMgr  anauth.RegManager
}

func NewOrgServer(c ec.Curve, secKey *psys.SecKey, pubKey *PubKey, caPubKey *psys.PubKey) *OrgServer {
	return &OrgServer{
		pubKey:       pubKey,
		NymGenerator: NewNymGenerator(caPubKey, c),
		CredIssuer:   NewCredIssuer(secKey, c),
		CredVerifier: NewCredVerifier(secKey, c),
	}
}

func (s *OrgServer) GenerateNym(stream pb.Org_EC_GenerateNymServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	pRandData := req.GetProofRandData()

	regKeyOk, err := s.RegMgr.CheckRegistrationKey(pRandData.RegKey)
	if !regKeyOk || err != nil {
		//s.Logger.Debugf("Registration key %s ok=%t, error=%v", pRandData.RegKey, regKeyOk, err)
		return status.Error(codes.NotFound, "registration key verification failed")

	}
	challenge, err := s.NymGenerator.GetChallenge(
		toECGroupElement(pRandData.A1), // TODO call it nym a
		toECGroupElement(pRandData.A2), // TODO call it blinded a
		toECGroupElement(pRandData.B1), // TODO call it nym b
		toECGroupElement(pRandData.B2), // TODO call it blinded b
		toECGroupElement(pRandData.X1),
		toECGroupElement(pRandData.X2),
		new(big.Int).SetBytes(pRandData.R),
		new(big.Int).SetBytes(pRandData.S),
	)
	if err != nil {
		//s.Logger.Debug(err)
		return status.Error(codes.Internal, err.Error())
	}

	if err := stream.Send(
		&psyspb.GenerateNymResponse{
			Type: &psyspb.GenerateNymResponse_Decommitment{
				Decommitment: &psyspb.PedersenDecommitment{
					X: challenge.Bytes(),
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
		&psyspb.GenerateNymResponse{
			Type: &psyspb.GenerateNymResponse_Success{
				Success: valid,
			},
		})
}

func (s *OrgServer) ObtainCred(stream pb.Org_EC_ObtainCredServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	pRandData := req.GetProofRandData()
	ch := s.CredIssuer.GetChallenge(
		toECGroupElement(pRandData.A),
		toECGroupElement(pRandData.B),
		toECGroupElement(pRandData.X),
	)

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
					X11: toPbECGroupElement(x11),
					X12: toPbECGroupElement(x12),
					X21: toPbECGroupElement(x21),
					X22: toPbECGroupElement(x22),
					A:   toPbECGroupElement(A),
					B:   toPbECGroupElement(B),
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
				ProofData: &psyspb.BytesPair{ // TODO remove dependency...
					X: z1.Bytes(),
					Y: z2.Bytes(),
				},
			},
		})
}

func (s *OrgServer) TransferCred(stream pb.Org_EC_TransferCredServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	pRandData := req.GetProofRandData()

	t1 := ecschnorr.NewBlindedTrans(
		new(big.Int).SetBytes(pRandData.Cred.T1.A.X),
		new(big.Int).SetBytes(pRandData.Cred.T1.A.Y),
		new(big.Int).SetBytes(pRandData.Cred.T1.B.X),
		new(big.Int).SetBytes(pRandData.Cred.T1.B.Y),
		new(big.Int).SetBytes(pRandData.Cred.T1.Hash),
		new(big.Int).SetBytes(pRandData.Cred.T1.ZAlpha))

	t2 := ecschnorr.NewBlindedTrans(
		new(big.Int).SetBytes(pRandData.Cred.T2.A.X),
		new(big.Int).SetBytes(pRandData.Cred.T2.A.Y),
		new(big.Int).SetBytes(pRandData.Cred.T2.B.X),
		new(big.Int).SetBytes(pRandData.Cred.T2.B.Y),
		new(big.Int).SetBytes(pRandData.Cred.T2.Hash),
		new(big.Int).SetBytes(pRandData.Cred.T2.ZAlpha))

	credential := NewCred(
		toECGroupElement(pRandData.Cred.SmallAToGamma),
		toECGroupElement(pRandData.Cred.SmallBToGamma),
		toECGroupElement(pRandData.Cred.AToGamma),
		toECGroupElement(pRandData.Cred.BToGamma),
		t1, t2,
	)

	ch := s.CredVerifier.GetChallenge(
		toECGroupElement(pRandData.NymA),
		toECGroupElement(pRandData.NymB),
		credential.SmallAToGamma,
		credential.SmallBToGamma,
		toECGroupElement(pRandData.X1),
		toECGroupElement(pRandData.X2),
	)

	if err := stream.Send(
		&psyspb.TransferCredResponse{
			Type: &psyspb.TransferCredResponse_Challenge{
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

	// TODO CredVerifier should be bound to an org with given pubkeys?
	if verified := s.CredVerifier.Verify(z, credential, s.pubKey); !verified {
		//s.Logger.Debug("User authentication failed")
		return status.Error(codes.Unauthenticated, "user authentication failed")
	}

	sessionKey, err := s.SessMgr.GenerateSessionKey()
	if err != nil {
		//s.Logger.Debug(err)
		return status.Error(codes.Internal, "failed to obtain session key")
	}

	return stream.Send(
		&psyspb.TransferCredResponse{
			Type: &psyspb.TransferCredResponse_SessionKey{
				SessionKey: *sessionKey,
			},
		})
}
