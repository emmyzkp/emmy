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
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis"

	"github.com/spf13/viper"

	"github.com/emmyzkp/emmy/anauth"
	pb "github.com/emmyzkp/emmy/anauth/cl/clpb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"math/big"

	"github.com/emmyzkp/crypto/df"
	"github.com/emmyzkp/crypto/qr"
	"github.com/emmyzkp/crypto/schnorr"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type Server struct {
	ReceiverRecordManager
	*Org

	attrs     []CredAttr
	attrCount *AttrCount

	config *viper.Viper

	SessMgr anauth.SessManager
	SessStorer anauth.SessStorer
	RegMgr  anauth.RegManager
	DataFetcher AttrDataFetcher
}

type AttrDataFetcher interface{
	FetchAttrData()(map[string]interface{}, error)
}

type RedisDataFetcher struct {
	*redis.Client
}

func NewRedisDataFetcher(c *redis.Client) *RedisDataFetcher {
	return &RedisDataFetcher{
		Client: c,
	}
}

func (f *RedisDataFetcher) FetchAttrData() (map[string]interface{}, error) {
	res, err := f.Get("validation").Result() // expected at fixed key
	if err != nil {
		return nil, err
	}

	var attrVals map[string]interface{}
	buf := bytes.NewBufferString(res)
	dec := json.NewDecoder(buf)
	dec.UseNumber()
	if err := dec.Decode(&attrVals); err != nil {
		return nil, errors.Wrap(err, "unable to read reference values of attributes")
	}

	for i, v := range attrVals {
		switch t := v.(type) {
		case json.Number:
			n, err := t.Int64()
			if err != nil {
				return nil, err
			}
			attrVals[i] = n // enforce int64
		}
	}

	fmt.Println("reference data for validation", attrVals)
	return attrVals, nil
}

func NewServer(recMgr ReceiverRecordManager, keys *KeyPair,
	v *viper.Viper) (*Server, error) {
	params := GetDefaultParamSizes()

	org, err := NewOrgFromParams(params, keys)
	if err != nil {
		return nil, errors.Wrap(err, "error creating orgnization")
	}

	attrs, attrCount, err := parseAttrs(v)
	if err != nil {
		return nil, errors.Wrap(err, "cannot parse attributes specification")
	}

	fmt.Printf("attribute counts:\n%s", attrCount)

	if err := validateConfig(attrCount, keys.Pub); err != nil {
		return nil, errors.Wrap(err,
			"key does not match attribute specification")
	}

	fmt.Println("server accepts the following attributes:")
	for _, a := range attrs {
		fmt.Printf(" %s\n", a)
	}

	return &Server{
		ReceiverRecordManager: recMgr,
		Org:       org,
		config:    v,
		attrs:     attrs,
		attrCount: attrCount,
	}, nil
}

func (s *Server) RegisterTo(grpcSrv *grpc.Server) {
	pb.RegisterAnonCredsServer(grpcSrv, s)
}

func (s *Server) GetPublicParams(ctx context.Context,
	msg *pb.Empty) (*pb.PublicParams, error) {
	pk := s.Org.Keys.Pub
	group := pk.PedersenParams.Group

	credStructure, err := s.getCredStructure()
	if err != nil {
		return nil, status.Error(codes.Internal,
			"server cannot provide public params")
	}

	return &pb.PublicParams{
		PubKey: &pb.PubKey{
			N:           pk.N.Bytes(),
			S:           pk.S.Bytes(),
			Z:           pk.Z.Bytes(),
			RsKnown:     toByteSlices(pk.RsKnown),
			RsCommitted: toByteSlices(pk.RsCommitted),
			RsHidden:    toByteSlices(pk.RsHidden),
			PedersenParams: &pb.PedersenParams{
				SchnorrGroup: &pb.SchnorrGroup{
					P: group.P.Bytes(),
					G: group.G.Bytes(),
					Q: group.Q.Bytes(),
				},
				H: pk.PedersenParams.H.Bytes(),
			},
			N1: pk.N1.Bytes(),
			G:  pk.G.Bytes(),
			H:  pk.H.Bytes(),
		},
		Params:        s.Params,
		CredStructure: credStructure,
	}, nil
}

func (s *Server) GetAcceptableCreds(ctx context.Context,
	msg *pb.Empty) (*pb.AcceptableCreds, error) {
	if !s.config.IsSet("acceptable_creds") {
		return nil, status.Error(codes.Internal,
			"unable to provide acceptable credentials info")
	}

	acceptable := s.config.GetStringMapStringSlice("acceptable_creds")
	ac := make([]*pb.AcceptableCred, 0)
	for k, v := range acceptable {
		ac = append(ac, &pb.AcceptableCred{
			OrgName:       k,
			RevealedAttrs: v,
		})
	}

	return &pb.AcceptableCreds{
		Creds: ac,
	}, nil
}

func (s *Server) getCredStructure() (*pb.CredStructure, error) {
	credAttrs := make([]*pb.CredAttribute, len(s.attrs))

	for i, a := range s.attrs {
		attr := &pb.Attribute{
			Index: int32(i),
			Name:  a.Name(),
			Known: a.isKnown(),
		}
		switch a.(type) {
		case *StrAttr:
			credAttrs[i] = &pb.CredAttribute{
				Type: &pb.CredAttribute_StringAttr{
					StringAttr: &pb.StringAttribute{
						Attr: attr,
					},
				},
			}
		case *Int64Attr:
			credAttrs[i] = &pb.CredAttribute{
				Type: &pb.CredAttribute_IntAttr{
					IntAttr: &pb.IntAttribute{
						Attr: attr,
					},
				},
			}
		}
	}

	return &pb.CredStructure{
		NKnown:     int32(s.attrCount.Known),
		NCommitted: int32(s.attrCount.Committed),
		NHidden:    int32(s.attrCount.Hidden),
		Attributes: credAttrs,
	}, nil
}

func (s *Server) Issue(stream pb.AnonCreds_IssueServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	regKeyOk, err := s.RegMgr.CheckRegistrationKey(req.GetRegKey())
	fmt.Println("checking reg key", req.GetRegKey())
	if err != nil {
		//s.Logger.Debugf("registration key %s ok=%t, error=%v",
		//	proofRandData.RegKey, regKeyOk, err)
		return status.Error(codes.Internal, "something went wrong")
	}
	if !regKeyOk {
		return status.Error(codes.NotFound, "registration key verification failed")
	}

	nonce := s.GetCredIssueNonce()
	resp := &pb.Response{
		Type: &pb.Response_Nonce{
			Nonce: nonce.Bytes(),
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	req, err = stream.Recv()
	if err != nil {
		return err
	}

	reqIssue := req.GetCredIssue()

	nymProof := schnorr.NewProof(
		new(big.Int).SetBytes(reqIssue.NymProof.ProofRandomData),
		new(big.Int).SetBytes(reqIssue.NymProof.Challenge),
		fromByteSlices(reqIssue.NymProof.ProofData),
	)

	uProofData, err := fromStringSlices(reqIssue.UProof.ProofData)
	if err != nil {
		return err
	}
	UProof := qr.NewRepresentationProof(
		new(big.Int).SetBytes(reqIssue.UProof.ProofRandomData),
		new(big.Int).SetBytes(reqIssue.UProof.Challenge),
		uProofData,
	)

	commitmentsOfAttrsProofs := make([]*df.OpeningProof, len(reqIssue.CommitmentsOfAttrsProofs))
	for i, proof := range reqIssue.CommitmentsOfAttrsProofs {
		commitmentsOfAttrsProofs[i] = df.NewOpeningProof(
			new(big.Int).SetBytes(proof.ProofRandomData),
			new(big.Int).SetBytes(proof.Challenge),
			new(big.Int).SetBytes(proof.ProofData[0]),
			new(big.Int).SetBytes(proof.ProofData[1]),
		)
	}

	cReq := NewCredRequest(
		new(big.Int).SetBytes(reqIssue.Nym),
		fromByteSlices(reqIssue.KnownAttrs),
		fromByteSlices(reqIssue.CommitmentsOfAttrs),
		nymProof,
		new(big.Int).SetBytes(reqIssue.U),
		UProof,
		commitmentsOfAttrsProofs,
		new(big.Int).SetBytes(reqIssue.Nonce),
	)

	// Issue the credential
	res, err := s.IssueCred(cReq)
	if err != nil {
		return fmt.Errorf("error when issuing credential: %v", err)
	}

	// Store the newly obtained receiver record to the database
	if err = s.Store(cReq.Nym, res.Record); err != nil {
		return err
	}

	resp = &pb.Response{
		Type: &pb.Response_IssuedCred{
			IssuedCred: &pb.IssuedCred{
				Cred: &pb.Cred{
					A:   res.Cred.A.Bytes(),
					E:   res.Cred.E.Bytes(),
					V11: res.Cred.V11.Bytes(),
				},
				AProof: &pb.FiatShamirAlsoNeg{
					ProofRandomData: res.AProof.ProofRandomData.Bytes(),
					Challenge:       res.AProof.Challenge.Bytes(),
					ProofData:       []string{res.AProof.ProofData[0].String()},
				},
			},
		},
	}

	return stream.Send(resp)
}

func (s *Server) Update(ctx context.Context, req *pb.CredUpdateRequest) (*pb.IssuedCred, error) {
	nym := new(big.Int).SetBytes(req.Nym)

	// Retrieve the receiver record from the database
	rec, err := s.Load(nym)
	if err != nil {
		return nil, err
	}

	// Do credential update
	res, err := s.UpdateCred(
		nym,
		rec,
		new(big.Int).SetBytes(req.Nonce),
		fromByteSlices(req.NewKnownAttrs),
	)
	if err != nil {
		return nil, fmt.Errorf("error when updating credential: %v", err)
	}

	// Store the updated receiver record to the database
	if err = s.Store(nym, res.Record); err != nil {
		return nil, err
	}

	return &pb.IssuedCred{
		Cred: &pb.Cred{
			A:   res.Cred.A.Bytes(),
			E:   res.Cred.E.Bytes(),
			V11: res.Cred.V11.Bytes(),
		},
		AProof: &pb.FiatShamirAlsoNeg{
			ProofRandomData: res.AProof.ProofRandomData.Bytes(),
			Challenge:       res.AProof.Challenge.Bytes(),
			ProofData:       []string{res.AProof.ProofData[0].String()},
		},
	}, nil
}

func (s *Server) Prove(stream pb.AnonCreds_ProveServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	nonce := s.GetProveCredNonce()
	resp := &pb.Response{
		Type: &pb.Response_Nonce{
			Nonce: nonce.Bytes(),
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	req, err = stream.Recv()
	if err != nil {
		return err
	}

	pReq := req.GetCredProve()

	knownAttrs := make([]*big.Int, len(pReq.KnownAttrs))
	for i, a := range pReq.KnownAttrs {
		knownAttrs[i] = new(big.Int).SetBytes(a)
	}

	commitmentsOfAttrs := make([]*big.Int, len(pReq.CommitmentsOfAttrs))
	for i, a := range pReq.CommitmentsOfAttrs {
		commitmentsOfAttrs[i] = new(big.Int).SetBytes(a)
	}

	pData, err := fromStringSlices(pReq.Proof.ProofData)
	if err != nil {
		return err
	}

	revealedKnownAttrsIndices := make([]int, len(pReq.RevealedKnownAttrs))
	for i, a := range pReq.RevealedKnownAttrs {
		revealedKnownAttrsIndices[i] = int(a)
	}

	revealedCommitmentsOfAttrsIndices := make([]int, len(pReq.RevealedCommitmentsOfAttrs))
	for i, a := range pReq.RevealedCommitmentsOfAttrs {
		revealedCommitmentsOfAttrsIndices[i] = int(a)
	}

	toValidate, err := s.DataFetcher.FetchAttrData()
	if err != nil {
		return err
	}

	verified, err := s.ProveCred(
		new(big.Int).SetBytes(pReq.A),
		qr.NewRepresentationProof(
			new(big.Int).SetBytes(pReq.Proof.ProofRandomData),
			new(big.Int).SetBytes(pReq.Proof.Challenge),
			pData),
		revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices,
		knownAttrs,
		commitmentsOfAttrs,
		s.attrs,
		toValidate,
	)
	if err != nil {
		return err
	}

	if !verified {
		//s.Logger.Debug("User authentication failed")
		return status.Error(codes.Unauthenticated, "user authentication failed")
	}

	sessKey, err := s.SessMgr.GenerateSessionKey()
	if err != nil {
		//s.Logger.Debug(err)
		return status.Error(codes.Internal, "failed to obtain session key")
	}

	// Store the session key along with Known attributes to the db
	// For integration with application logic
	if err = s.SessStorer.Store(*sessKey); err != nil {
		fmt.Println(err)
		return status.Error(codes.Internal,
			"the server could not finish the proof")
	}

	return stream.Send(
		&pb.Response{
			Type: &pb.Response_SessionKey{
				SessionKey: *sessKey,
			},
		})
}

// validateConfig checks that there are no discrepancies in configuration
// of public key pertaining the organization tied to this server, and the
// expected counts of attributes.
func validateConfig(n *AttrCount, pk *PubKey) error {
	if n.Known != len(pk.RsKnown) {
		return fmt.Errorf("expected %d Known attributes, found %d",
			n.Known, len(pk.RsKnown))
	}
	if n.Committed != len(pk.RsCommitted) {
		return fmt.Errorf("expected %d Committed attributes, found %d",
			n.Committed, len(pk.RsCommitted))
	}
	if n.Hidden != len(pk.RsHidden) {
		return fmt.Errorf("expected %d Hidden attributes, found %d",
			n.Hidden, len(pk.RsHidden))
	}

	return nil
}

func fromByteSlices(s [][]byte) []*big.Int {
	res := make([]*big.Int, len(s))
	for i, si := range s {
		res[i] = new(big.Int).SetBytes(si)
	}

	return res
}

func fromStringSlices(s []string) ([]*big.Int, error) {
	res := make([]*big.Int, len(s))
	for i, si := range s {
		x, ok := new(big.Int).SetString(si, 10)
		if !ok {
			return nil, fmt.Errorf("error when initializing big.Int from string")
		}
		res[i] = x
	}

	return res, nil
}
