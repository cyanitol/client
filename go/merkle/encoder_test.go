package merkle

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func dummy(i int) []byte {
	return bytes.Repeat([]byte{byte(i)}, 32)
}
func dummy16(i int) (ret [16]byte) {
	x := dummy(i)
	copy(ret[:], x)
	return ret
}
func dummy32(i int) (ret [32]byte) {
	x := dummy(i)
	copy(ret[:], x)
	return ret
}

func TestEncode(t *testing.T) {
	var tests = []struct {
		desc            string
		encodingType    EncodingType
		leaf            Leaf
		key             []byte
		secret          []byte
		expectedBlinder []byte
	}{
		{
			desc:         "basic",
			encodingType: EncodingTypeBlindedSHA512_256v1,
			leaf: Chain17v1Leaf{
				TeamID: dummy16(0),
				SigID:  dummy(1),
				LinkID: dummy32(2),
				Seqno:  123,
			},
			key:    dummy(3),
			secret: dummy(4),
			expectedBlinder: []byte{0x1a, 0x3d, 0xf7, 0xf8, 0x60, 0xb8, 0x6f,
				0x53, 0x3e, 0x3b, 0x28, 0xfd, 0x6, 0xa, 0xf2, 0x24, 0x4, 0x8d,
				0x3c, 0xca, 0x7a, 0x7b, 0x59, 0x76, 0x1, 0xcf, 0x1d, 0xe4, 0x77,
				0x20, 0x9, 0xc7},
		},
		{
			desc:         "ensure different secret produces different blinder with same leaf",
			encodingType: EncodingTypeBlindedSHA512_256v1,
			leaf: Chain17v1Leaf{
				TeamID: dummy16(0),
				SigID:  dummy(1),
				LinkID: dummy32(2),
				Seqno:  123,
			},
			key:    dummy(3),
			secret: dummy(5),
			expectedBlinder: []byte{0xf2, 0x44, 0xe3, 0xb1, 0x61, 0xeb, 0x2,
				0x7e, 0x2, 0xbc, 0x60, 0x3, 0x9e, 0xec, 0xdd, 0x1b, 0x70, 0xa6,
				0x57, 0x89, 0xfe, 0x93, 0xa7, 0xde, 0xd4, 0x7c, 0xb, 0x56, 0xbc,
				0xcb, 0x83, 0x27},
		},
		{
			desc:         "ensure different leaf produces different blinder with same secret",
			encodingType: EncodingTypeBlindedSHA512_256v1,
			leaf: Chain17v1Leaf{
				TeamID: dummy16(0),
				SigID:  dummy(1),
				LinkID: dummy32(3),
				Seqno:  123,
			},
			key:    dummy(3),
			secret: dummy(4),
			expectedBlinder: []byte{0xd1, 0x91, 0x3e, 0xfe, 0xdb, 0xc9, 0x7,
				0xc8, 0x67, 0xe1, 0x73, 0x5, 0x86, 0x50, 0xe3, 0xb4, 0xde, 0x1f,
				0x13, 0x53, 0x24, 0xd5, 0xfc, 0xce, 0xc3, 0xbd, 0x2d, 0xec, 0x13,
				0x5e, 0x3f, 0x5},
		},
	}
	for _, tt := range tests {
		e := NewEncoder(tt.encodingType)
		t.Run(tt.desc, func(t *testing.T) {
			blinder, err := e.Encode(tt.leaf, NewKey(tt.key), NewSecret(tt.secret))
			require.NoError(t, err)
			require.Equal(t, tt.expectedBlinder, blinder)

			preimage, err := e.BlindedPreimage(tt.leaf, NewKey(tt.key), NewSecret(tt.secret))
			require.NoError(t, err)
			blinder2, err := e.Hash(preimage)
			require.NoError(t, err)
			require.Equal(t, blinder, blinder2, "got same blinder via validation route")
		})
	}

}

func TestGenerateSecret(t *testing.T) {
	e := NewEncoder(EncodingTypeBlindedSHA512_256v1)
	x, err := e.GenerateSecret()
	require.NoError(t, err)
	y, err := e.GenerateSecret()
	require.NoError(t, err)

	require.NotEqual(t, x, y)
}
