// Copyright 2019, 2020 Weald Technology Trading
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

package util

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	bytesutil "github.com/wealdtech/go-bytesutil"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	"golang.org/x/crypto/hkdf"
)

func _bigInt(input string) *big.Int {
	result, _ := new(big.Int).SetString(input, 10)
	return result
}

var (
	r = _bigInt("52435875175126190479447740508185965837690552500527637822603658699938581184513")
	// 48 comes from ceil((1.5 * ceil(log2(r))) / 8)
	l = 48
)

func validateRelativePath(relativePath string) bool {
	match, _ := regexp.MatchString(`^(\/(\d\d?\d?\d?\d?\d?))+$`, relativePath)
	return match
}

func validateMasterKeyPath(path string) bool {
	match, _ := regexp.MatchString(`^m\/`, path)
	return match
}

func PrivateKeyForRelativePath(key []byte, relativePath string) (*e2types.BLSPrivateKey, error) {
	if validateMasterKeyPath(relativePath) {
		return nil, fmt.Errorf("basePath invalid, not relative. if you need to derive basePath from seed please use PrivateKeyFromSeedAndPath")
	}
	if !validateRelativePath(relativePath) {
		return nil, fmt.Errorf("relative basePath invalid: %s", relativePath)
	}

	pathBits := strings.Split(relativePath, "/")
	sk := new(big.Int).SetBytes(key)
	for i := 1 ; i < len(pathBits) ; i++ { // we skip index 0 as it's empty for relative paths
		if pathBits[i] == "" {
			return nil, fmt.Errorf("no entry at basePath component %d", i)
		}

		index, err := strconv.ParseInt(pathBits[i], 10, 32)
		if err != nil || index < 0 {
			return nil, fmt.Errorf("invalid index %q at basePath component %d", pathBits[i], i)
		}
		sk, err = DeriveChildSK(sk, uint32(index))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to derive child SK at basePath component %d", i)
		}
	}

	// SK can be shorter than 32 bytes so left-pad it here.
	bytes := make([]byte, 32)
	skBytes := sk.Bytes()
	copy(bytes[32-len(skBytes):], skBytes)

	return e2types.BLSPrivateKeyFromBytes(bytes)
}

// PrivateKeyFromSeedAndPath generates a private key given a seed and a basePath.
// Follows ERC-2334.
func PrivateKeyFromSeedAndPath(seed []byte, path string) (*e2types.BLSPrivateKey, error) {
	if len(seed) < 16 {
		return nil, errors.New("seed must be at least 128 bits")
	}
	if !validateMasterKeyPath(path) {
		return nil,fmt.Errorf("invalid basePath, should start with m/<index>")
	}

	// derive master key
	sk, err := DeriveMasterSK(seed)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate master key")
	}

	if len(path) > 2 { // try to derive child keys
		relativePath := strings.Replace(path,"m","",1)
		return PrivateKeyForRelativePath(sk.Bytes(),relativePath)
	} else { // derive just seed to master
		return e2types.BLSPrivateKeyFromBytes(sk.Bytes())
	}
}

// DeriveMasterSK derives the master secret key from a seed.
// Follows ERC-2333.
func DeriveMasterSK(seed []byte) (*big.Int, error) {
	if len(seed) < 16 {
		return nil, errors.New("seed must be at least 128 bits")
	}
	return hkdfModR(seed, "")
}

// DeriveChildSK derives the child secret key from a parent key.
// Follows ERC-2333.
func DeriveChildSK(parentSK *big.Int, index uint32) (*big.Int, error) {
	pk, err := parentSKToLamportPK(parentSK, index)
	if err != nil {
		return nil, err
	}
	return hkdfModR(pk, "")
}

// ikmToLamportSK creates a Lamport secret key.
func ikmToLamportSK(ikm []byte, salt []byte) ([255][32]byte, error) {
	prk := hkdf.Extract(sha256.New, ikm, salt)
	okm := hkdf.Expand(sha256.New, prk, nil)
	var lamportSK [255][32]byte
	for i := 0; i < 255; i++ {
		var result [32]byte
		read, err := okm.Read(result[:])
		if err != nil {
			return lamportSK, err
		}
		if read != 32 {
			return lamportSK, fmt.Errorf("only read %d bytes", read)
		}
		lamportSK[i] = result
	}

	return lamportSK, nil
}

// parentSKToLamportPK generates the Lamport private key from a BLS secret key.
func parentSKToLamportPK(parentSK *big.Int, index uint32) ([]byte, error) {
	salt := i2OSP(big.NewInt(int64(index)), 4)
	ikm := i2OSP(parentSK, 32)
	lamport0, err := ikmToLamportSK(ikm, salt)
	if err != nil {
		return nil, err
	}
	notIKM := bytesutil.XOR(ikm)
	lamport1, err := ikmToLamportSK(notIKM, salt)
	if err != nil {
		return nil, err
	}
	lamportPK := make([]byte, (255+255)*32)
	for i := 0; i < 255; i++ {
		copy(lamportPK[32*i:], SHA256(lamport0[i][:]))
	}
	for i := 0; i < 255; i++ {
		copy(lamportPK[(i+255)*32:], SHA256(lamport1[i][:]))
	}
	compressedLamportPK := SHA256(lamportPK)
	return compressedLamportPK, nil
}

// hkdfModR hashes 32 random bytes into the subgroup of the BLS12-381 private keys.
func hkdfModR(ikm []byte, keyInfo string) (*big.Int, error) {
	prk := hkdf.Extract(sha256.New, append(ikm, i2OSP(big.NewInt(0), 1)...), []byte("BLS-SIG-KEYGEN-SALT-"))
	okm := hkdf.Expand(sha256.New, prk, append([]byte(keyInfo), i2OSP(big.NewInt(int64(l)), 2)...))
	okmOut := make([]byte, l)
	read, err := okm.Read(okmOut)
	if err != nil {
		return nil, err
	}
	if read != l {
		return nil, fmt.Errorf("only read %d bytes", read)
	}
	return new(big.Int).Mod(osToIP(okmOut), r), nil
}

// osToIP turns a byte array in to an integer as per https://ietf.org/rfc/rfc3447.txt
func osToIP(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

// i2OSP turns an integer in to a byte array as per https://ietf.org/rfc/rfc3447.txt
func i2OSP(data *big.Int, resLen int) []byte {
	res := make([]byte, resLen)
	bytes := data.Bytes()
	copy(res[resLen-len(bytes):], bytes)
	return res
}
