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

package commitmentzkp

import (
	"math/big"

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
)

type DFCommitmentOpeningProver struct {
	committer          *commitments.DamgardFujisakiCommitter
	challengeSpaceSize int
	r1                 *big.Int
	r2                 *big.Int
}

func NewDFCommitmentOpeningProver(committer *commitments.DamgardFujisakiCommitter,
	challengeSpaceSize int) *DFCommitmentOpeningProver {
	return &DFCommitmentOpeningProver{
		committer:          committer,
		challengeSpaceSize: challengeSpaceSize,
	}
}

func (p *DFCommitmentOpeningProver) GetProofRandomData() *big.Int {
	// r1 from [0, T * 2^(NLength + ChallengeSpaceSize))
	nLen := p.committer.QRSpecialRSA.N.BitLen()
	exp := big.NewInt(int64(nLen + p.challengeSpaceSize))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	b.Mul(b, p.committer.T)
	r1 := common.GetRandomInt(b)
	p.r1 = r1
	// r2 from [0, 2^(B + 2*NLength + ChallengeSpaceSize))
	b = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(
		p.committer.B+2*nLen+p.challengeSpaceSize)), nil)
	r2 := common.GetRandomInt(b)
	p.r2 = r2
	// G^r1 * H^r2
	proofRandomData := p.committer.ComputeCommit(r1, r2)
	return proofRandomData
}

func (p *DFCommitmentOpeningProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int) {
	// s1 = r1 + challenge*a (in Z, not modulo)
	// s2 = r2 + challenge*r (in Z, not modulo)
	a, r := p.committer.GetDecommitMsg()
	s1 := new(big.Int).Mul(challenge, a)
	s1.Add(s1, p.r1)
	s2 := new(big.Int).Mul(challenge, r)
	s2.Add(s2, p.r2)
	return s1, s2
}

// DFOpeningProof presents all three messages in sigma protocol - useful when challenge
// is generated by prover via Fiat-Shamir.
type DFOpeningProof struct {
	ProofRandomData *big.Int
	Challenge       *big.Int
	ProofData1      *big.Int
	ProofData2      *big.Int
}

func NewDFOpeningProof(proofRandomData, challenge, proofData1, proofData2 *big.Int) *DFOpeningProof {
	return &DFOpeningProof{
		ProofRandomData: proofRandomData,
		Challenge:       challenge,
		ProofData1:      proofData1,
		ProofData2:      proofData2,
	}
}

type DFCommitmentOpeningVerifier struct {
	receiver           *commitments.DamgardFujisakiReceiver
	challengeSpaceSize int
	challenge          *big.Int
	proofRandomData    *big.Int
}

func NewDFCommitmentOpeningVerifier(receiver *commitments.DamgardFujisakiReceiver,
	challengeSpaceSize int) *DFCommitmentOpeningVerifier {
	return &DFCommitmentOpeningVerifier{
		receiver:           receiver,
		challengeSpaceSize: challengeSpaceSize,
	}
}

func (v *DFCommitmentOpeningVerifier) SetProofRandomData(proofRandomData *big.Int) {
	v.proofRandomData = proofRandomData
}

func (v *DFCommitmentOpeningVerifier) GetChallenge() *big.Int {
	exp := big.NewInt(int64(v.challengeSpaceSize))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	challenge := common.GetRandomInt(b)
	v.challenge = challenge
	return challenge
}

// SetChallenge is used when Fiat-Shamir is used - when challenge is generated using hash by the prover.
func (v *DFCommitmentOpeningVerifier) SetChallenge(challenge *big.Int) {
	v.challenge = challenge
}

func (v *DFCommitmentOpeningVerifier) Verify(s1, s2 *big.Int) bool {
	// verify proofRandomData * verifier.receiver.Commitment^challenge = G^s1 * H^s2 mod n
	left := v.receiver.QRSpecialRSA.Exp(v.receiver.Commitment, v.challenge)
	left = v.receiver.QRSpecialRSA.Mul(v.proofRandomData, left)
	right := v.receiver.ComputeCommit(s1, s2)
	return left.Cmp(right) == 0
}
