// Copyright © 2019 Weald Technology Trading
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util_test

import (
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	util "github.com/wealdtech/go-eth2-util"
)

func _bigInt(input string) *big.Int {
	res, _ := new(big.Int).SetString(input, 10)
	return res
}

func _byteArray(input string) []byte {
	res, _ := hex.DecodeString(input)
	return res
}

func TestMain(m *testing.M) {
	if err := e2types.InitBLS(); err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestPrivateKeyFromSeedAndPath(t *testing.T) {
	tests := []struct {
		name string
		seed []byte
		path string
		err  error
		sk   *big.Int
	}{
		{
			name: "Nil",
			err:  errors.New("no path"),
		},
		{
			name: "EmptyPath",
			path: "",
			err:  errors.New("no path"),
		},
		{
			name: "EmptySeed",
			path: "m/12381/3600/0/0",
			err:  errors.New("seed must be at least 128 bits"),
		},
		{
			name: "BadPath1",
			seed: _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			path: "m/bad path",
			err:  errors.New(`invalid index "bad path" at path component 1`),
		},
		{
			name: "BadPath2",
			seed: _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			path: "m/m/12381",
			err:  errors.New(`invalid master at path component 1`),
		},
		{
			name: "BadPath3",
			seed: _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			path: "1/m/12381",
			err:  errors.New(`not master at path component 0`),
		},
		{
			name: "BadPath4",
			seed: _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			path: "m/12381//0",
			err:  errors.New(`no entry at path component 2`),
		},
		{
			name: "BadPath5",
			seed: _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			path: "m/12381/-1/0",
			err:  errors.New(`invalid index "-1" at path component 2`),
		},
		{
			name: "Good1",
			seed: _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			path: "m/12381/3600/0/0",
			sk:   _bigInt("19075636639719741300162348744159133165933652615166291241450015728146974697031"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sk, err := util.PrivateKeyFromSeedAndPath(test.seed, test.path)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				// fmt.Printf("%v\n", new(big.Int).SetBytes(sk.Marshal()))
				assert.Equal(t, test.sk.Bytes(), sk.Marshal())
			}
		})
	}
}

func TestShortPrivateKey(t *testing.T) {
	seed := _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	path := "m/12381/3600/0/41"
	_, err := util.PrivateKeyFromSeedAndPath(seed, path)
	assert.Nil(t, err)
}

func TestDeriveMasterKey(t *testing.T) {
	tests := []struct {
		name string
		seed []byte
		err  error
		sk   *big.Int
	}{
		{
			name: "ShortSeed",
			seed: _byteArray("0102030405060708090a0b0c0d0e"),
			err:  errors.New("seed must be at least 128 bits"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sk, err := util.DeriveMasterSK(test.seed)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				assert.Equal(t, test.sk, sk)
			}
		})
	}
}

func TestDeriveChildKey(t *testing.T) {
	tests := []struct {
		name       string
		seed       []byte
		childIndex uint32
		err        error
		childSK    *big.Int
	}{
		// TODO
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			masterSK, err := util.DeriveMasterSK(test.seed)
			require.Nil(t, err)
			childSK, err := util.DeriveChildSK(masterSK, test.childIndex)
			if test.err != nil {
				require.NotNil(t, err)
				require.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				assert.Equal(t, test.childSK, childSK)
			}
		})
	}
}
