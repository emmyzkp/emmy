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

import pb "github.com/emmyzkp/emmy/anauth/cl/clpb"

// TODO: add method to load params from file or blockchain or wherever they will be stored.
func GetDefaultParamSizes() *pb.Params {
	return &pb.Params{
		RhoBitLen:      256,
		NLength:        256, // should be at least 2048 when not testing
		AttrBitLen:     256,
		HashBitLen:     512,
		SecParam:       80,
		EBitLen:        597,
		E1BitLen:       120,
		VBitLen:        2724,
		ChallengeSpace: 80,
	}
}

// PubParams keeps all the public parameters for the scheme.
// These can be propagated from the server to the client.
type PubParams struct {
	PubKey  *PubKey
	RawCred *RawCred // contains credential structure
	Config  *pb.Params
}
