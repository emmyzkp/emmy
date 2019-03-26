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

package test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spf13/viper"

	"google.golang.org/grpc"

	"github.com/emmyzkp/emmy/anauth"
	"github.com/emmyzkp/emmy/anauth/cl"
	pb "github.com/emmyzkp/emmy/anauth/cl/clpb"
)

func TestEndToEnd_CL(t *testing.T) {
	tests := []struct {
		desc            string
		params          *pb.Params
		acceptableCreds map[string][]string
		attributes      map[string]interface{}
		referenceVals map[string]interface{}
	}{
		{"Defaults",
			cl.GetDefaultParamSizes(),
			map[string][]string{
				"org1": {"name", "date_from", "date_to"},
				"org2": {"gender"},
			},
			map[string]interface{}{
				"date_from": map[string]interface{}{
					"index": 0,
					"type": "int64",
					"cond": "gte",
				},
				"date_to":   map[string]interface{}{
					"index": 1,
					"type": "int64",
					"cond": "lte",
				},
				"name":      map[string]interface{}{
					"index": 2,
					"type": "string",
				},
				"gender":    map[string]interface{}{
					"index": 3,
					"type": "string",
				},
				"graduated": map[string]interface{}{
					"index": 4,
					"type": "string",
				},
				"age": map[string]interface{}{
					"index": 5,
					"type":  "int64",
					"known": "false",
				},
			},
			map[string]interface{}{
				"date_from": int64(1512643000),
				"date_to": int64(1592643000),
			},
		},
	}

	for _, tt := range tests {
		keys, err := cl.GenerateKeyPair(tt.params, cl.NewAttrCount(5, 1, 0))
		if err != nil {
			t.Errorf("error creating keypair: %v", err)
		}

		v := viper.New()
		v.Set("acceptable_creds", tt.acceptableCreds)
		v.Set("attributes", tt.attributes)

		clSrv, err := cl.NewServer(recDB, keys, v)
		if err != nil {
			t.Errorf("error creating cl server: %v", err)
		}

		dataStore := &testFetcher{}
		dataStore.fillWith(tt.referenceVals)
		sessionKeyStore := newTestStore()

		// FIXME
		clSrv.RegMgr = regKeyDB
		clSrv.SessMgr, _ = anauth.NewRandSessionKeyGen(32)
		clSrv.SessStorer = sessionKeyStore
		clSrv.DataFetcher = dataStore

		testSrv := newTestSrv()
		testSrv.addService(clSrv)
		go testSrv.start()

		conn, err := getTestConn()
		if err != nil {
			t.Errorf("cannot establish connection to test server: %v", err)
		}

		t.Run(tt.desc, func(t *testing.T) {
			testEndToEndCL(t, conn, sessionKeyStore)
		})

		conn.Close()
		testSrv.teardown()
	}
}

// TestCL requires a running server.
func testEndToEndCL(t *testing.T, conn *grpc.ClientConn,
	sessionKeyStore *testStorer) {
	client := cl.NewClient(conn)

	params, err := client.GetPublicParams()
	require.NoError(t, err)

	rc := params.RawCred
	err = rc.UpdateAttr("date_from", 1512643000)
	assert.NoError(t, err)
	err = rc.UpdateAttr("date_to", 1592643000)
	assert.NoError(t, err)
	err = rc.UpdateAttr("name", "Jack")
	assert.NoError(t, err)
	err = rc.UpdateAttr("gender", "M")
	assert.NoError(t, err)
	err = rc.UpdateAttr("graduated", "true")
	assert.NoError(t, err)
	err = rc.UpdateAttr("age", 50)
	assert.NoError(t, err)

	acceptableCreds, err := client.GetAcceptableCreds()
	require.NoError(t, err)
	revealedAttrs := acceptableCreds["org1"] // FIXME

	pubKey := params.PubKey
	masterSecret := pubKey.GenerateUserMasterSecret()

	fmt.Println("schemeParams", params.Config)
	fmt.Println("pubKey", pubKey)
	fmt.Println("rawCred", rc)

	cm, err := cl.NewCredManager(params.Config, pubKey, masterSecret, rc)
	require.NoError(t, err)

	regKey := "key1"
	regKeyDB.Insert(regKey)
	cred, err := client.IssueCredential(cm, regKey)
	require.NoError(t, err)

	// create new CredManager (updating or proving usually does not happen at the same time
	// as issuing)
	cm, err = cl.RestoreCredManager(cm.GetContext(), masterSecret, rc)
	require.NoError(t, err)

	sessKey, err := client.ProveCredential(cm, cred, revealedAttrs)
	require.NoError(t, err)
	assert.NotNil(t, sessKey, "possesion of a credential proof failed")
	assert.True(t, sessionKeyStore.contains(*sessKey))

	// modify some attributes and get updated credential
	err = rc.UpdateAttr("name", "Jim")
	assert.NoError(t, err)

	cred1, err := client.UpdateCredential(cm, rc)
	require.NoError(t, err)

	sessKey, err = client.ProveCredential(cm, cred1, revealedAttrs)
	require.NoError(t, err)
	assert.NotNil(t, sessKey, "possesion of an updated credential proof failed")
	assert.True(t, sessionKeyStore.contains(*sessKey))
}

type testFetcher struct {
	data map[string]interface{}
}
func (f *testFetcher) fillWith(data map[string]interface{}) {
	f.data = data
}
func (f *testFetcher) FetchAttrData() (map[string]interface{}, error) {
	return f.data, nil
}

type testSessStore interface {
	anauth.SessStorer
	contains(string) bool
}

type testStorer struct {
	data []string
}
func newTestStore() *testStorer {
	return &testStorer{
		data: make([]string, 0),
	}
}
func (s *testStorer) Store(k string) error {
	s.data = append(s.data, k)
	return nil
}

func (s *testStorer) contains(key string) bool {
	for _, k := range s.data {
		if key == k {
			return true
		}
	}
	return false
}

func intsToBig(s ...int) []*big.Int {
	bigS := make([]*big.Int, len(s))
	for i, el := range s {
		bigS[i] = big.NewInt(int64(el))
	}
	return bigS
}
