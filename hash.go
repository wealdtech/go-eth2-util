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

package util

import (
	"crypto/sha256"

	"golang.org/x/crypto/sha3"
)

// SHA3256 creates an SHA3-256 hash of the supplied data
func SHA3256(data ...[]byte) []byte {
	hash := sha3.New256()
	for _, d := range data {
		_, _ = hash.Write(d)
	}
	return hash.Sum(nil)
}

// SHA256 creates an SHA-256 hash of the supplied data
func SHA256(data ...[]byte) []byte {
	hash := sha256.New()
	for _, d := range data {
		_, _ = hash.Write(d)
	}
	return hash.Sum(nil)
}

// Keccak256 creates a Keccak256 hash of the supplied data
func Keccak256(data ...[]byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	for _, d := range data {
		_, _ = hash.Write(d)
	}
	return hash.Sum(nil)
}
