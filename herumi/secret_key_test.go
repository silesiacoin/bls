package herumi_test

import (
	rand2 "crypto/rand"
	"errors"
	"testing"

	"github.com/silesiacoin/bls/common"

	"github.com/silesiacoin/bls/bytesutil"
	"github.com/silesiacoin/bls/herumi"
	"github.com/silesiacoin/bls/testutil/assert"
	"github.com/silesiacoin/bls/testutil/require"
)

func TestGenerateKey(t *testing.T) {
	rand := rand2.Reader
	public, private, err := herumi.GenerateKey(rand)
	assert.NoError(t, err)
	assert.NotNil(t, public)
	assert.NotNil(t, private)
}

func TestMarshalUnmarshal(t *testing.T) {
	priv, err := herumi.RandKey()
	require.NoError(t, err)
	b := priv.Marshal()
	b32 := bytesutil.ToBytes32(b)
	pk, err := herumi.SecretKeyFromBytes(b32[:])
	require.NoError(t, err)
	pk2, err := herumi.SecretKeyFromBytes(b32[:])
	require.NoError(t, err)
	assert.DeepEqual(t, pk.Marshal(), pk2.Marshal())
}

func TestSecretKeyFromBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		err   error
	}{
		{
			name: "Nil",
			err:  errors.New("secret key must be 32 bytes"),
		},
		{
			name:  "Empty",
			input: []byte{},
			err:   errors.New("secret key must be 32 bytes"),
		},
		{
			name:  "Short",
			input: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:   errors.New("secret key must be 32 bytes"),
		},
		{
			name:  "Long",
			input: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:   errors.New("secret key must be 32 bytes"),
		},
		{
			name:  "Bad",
			input: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			err:   common.ErrSecretUnmarshal,
		},
		{
			name:  "Good",
			input: []byte{0x25, 0x29, 0x5f, 0x0d, 0x1d, 0x59, 0x2a, 0x90, 0xb3, 0x33, 0xe2, 0x6e, 0x85, 0x14, 0x97, 0x08, 0x20, 0x8e, 0x9f, 0x8e, 0x8b, 0xc1, 0x8f, 0x6c, 0x77, 0xbd, 0x62, 0xf8, 0xad, 0x7a, 0x68, 0x66},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := herumi.SecretKeyFromBytes(test.input)
			if test.err != nil {
				assert.ErrorContains(t, test.err.Error(), err)
			} else {
				assert.NoError(t, err)
				assert.DeepEqual(t, test.input, res.Marshal())
			}
		})
	}
}

func TestSerialize(t *testing.T) {
	rk, err := herumi.RandKey()
	require.NoError(t, err)
	b := rk.Marshal()

	_, err = herumi.SecretKeyFromBytes(b)
	assert.NoError(t, err)
}
