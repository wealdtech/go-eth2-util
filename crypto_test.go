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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			sk:   _bigInt("31676788419929922777864946442677915531199062343799598297489487887255736884383"),
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
		{
			name: "Spec0",
			seed: _byteArray("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
			sk:   _bigInt("12513733877922233913083619867448865075222526338446857121953625441395088009793"),
		},
		{
			name: "Spec1",
			seed: _byteArray("3141592653589793238462643383279502884197169399375105820974944592"),
			sk:   _bigInt("46029459550803682895343812821003080589696405386150182061394330539196052371668"),
		},
		{
			name: "Spec2",
			seed: _byteArray("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00"),
			sk:   _bigInt("45379166311535261329029945990467475187325618028073620882733843918126031931161"),
		},
		{
			name: "Spec3",
			seed: _byteArray("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
			sk:   _bigInt("8591296517642752610571443601667923790682754368613740552668934360711284428110"),
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
		{
			name:       "Spec0",
			seed:       _byteArray("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
			childIndex: 0,
			childSK:    _bigInt("7419543105316279183937430842449358701327973165530407166294956473095303972104"),
		},
		{
			name:       "Spec1",
			seed:       _byteArray("3141592653589793238462643383279502884197169399375105820974944592"),
			childIndex: 3141592653,
			childSK:    _bigInt("43469287647733616183478983885105537266268532274998688773496918571876759327260"),
		},
		{
			name:       "Spec2",
			seed:       _byteArray("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00"),
			childIndex: uint32(4294967295),
			childSK:    _bigInt("46475244006136701976831062271444482037125148379128114617927607151318277762946"),
		},
		{
			name:       "Spec3",
			seed:       _byteArray("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
			childIndex: 42,
			childSK:    _bigInt("51041472511529980987749393477251359993058329222191894694692317000136653813011"),
		},
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
