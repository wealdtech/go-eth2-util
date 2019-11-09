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
	"math/big"
	"testing"
)

//func TestIKMToSecret(t *testing.T) {
//	keys, err := ikmToLamportSK([]byte("secret"), []byte("salt"))
//	if err != nil {
//		t.Fatal(err)
//	}
//	for i := range keys {
//		fmt.Printf("%#x\n", keys[i])
//	}
//}

func TestOSToIP(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		output *big.Int
	}{
		{
			name:   "Nil",
			input:  nil,
			output: _bigInt("0"),
		},
		{
			name:   "Empty",
			input:  []byte{},
			output: _bigInt("0"),
		},
		{
			name:   "TestA",
			input:  []byte("a"),
			output: _bigInt("97"),
		},
		{
			name:   "TestAB",
			input:  []byte("ab"),
			output: _bigInt("24930"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := osToIP(test.input)
			if test.output.Cmp(output) != 0 {
				t.Errorf("Unexpected output: expected %v, received %v", test.output, output)
			}
		})
	}
}
