package herumi

import (
	"errors"
	common2 "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	bls12 "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/silesiacoin/bls/common"
	"github.com/silesiacoin/bls/testutil/assert"
	"github.com/silesiacoin/bls/testutil/require"
	"math/big"
	"testing"
)

func TestSignVerify(t *testing.T) {
	priv, err := RandKey()
	require.NoError(t, err)
	pub := priv.PublicKey()
	msg := []byte("hello")
	sig := priv.Sign(msg)

	privKey := priv.(*Bls12SecretKey)
	pubKey := pub.(*PublicKey)

	hexStringPrivKey := hexutil.Encode(privKey.Marshal())
	hexStringPubKey := hexutil.Encode(pubKey.Marshal())

	assert.NotNil(t, hexStringPrivKey)
	assert.NotNil(t, hexStringPubKey)

	// hexStringPrivKey 0x37d5bd689ca165b212e2c26200fbe3aac907d7398bbf01afd838bfb4c5bb15d5
	// HexStringPubKey 0x82af1c375a5604d618d15e6cf8909651e9533f26e701be2bd6686e808ec4c7bb10ab2859f7205d49eac67c72e3cdd631

	privKey1 := hexutil.MustDecode(hexStringPrivKey)
	pubKey1 := hexutil.MustDecode(hexStringPubKey)

	privKeyBls := new(bls12.SecretKey)
	err = privKeyBls.Deserialize(privKey1)
	assert.NoError(t, err)

	pubkeyBls := new(bls12.PublicKey)
	err = pubkeyBls.Deserialize(pubKey1)
	assert.NoError(t, err)
	assert.DeepEqual(t, true, sig.Verify(pub, msg))
}

func TestCompressSignVerify(t *testing.T) {
	privKey1 := hexutil.MustDecode("0x37d5bd689ca165b212e2c26200fbe3aac907d7398bbf01afd838bfb4c5bb15d5")
	pubKey1 := hexutil.MustDecode("0x82af1c375a5604d618d15e6cf8909651e9533f26e701be2bd6686e808ec4c7bb10ab2859f7205d49eac67c72e3cdd631")
	hexSignature := hexutil.MustDecode("0x8e542829726129846f78919a4802a17aed62e15e89ab1d77050aa4e7772e37b60cbb596027c62ee5389ad895331fc33500f86c2094d1ff7c25ebdb4f722f272b1d83eff3ab90c3169154039b17635f4fff377bb6ab2206b4d50f176c2b58c562")
	//hashOfXWithinSignature := hexutil.MustDecode("0x90095fcc94b90406e9072f648290f9c1bb5057595bddb4bb6cfae250250358cdf93c503e2c3bcdff7c623caac4683e03122a021357614d0d6e4a3b5dbab509d22f2fab50b8f2b18ad3b2a85ca614b7eafc88667746af8a5c72677c0ecead8a42")
	//hashOfMessage := hexutil.MustDecode("0xb9f44d5ffd045ca58dca2c711692fadf16b7fa5a4fd5c38b4b7bedb3ea67cfc587902e0b65078ac1c996c39ee351a80508188e87247fbf6f56e236d18521699e0c38c35c9e6ae65e81602dbbdb7a155eb21790a427232d682daf3ec3cb1ef569")
	generatorPubKey := hexutil.MustDecode("0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")

	priv := new(Bls12SecretKey)
	privBls := new(bls12.SecretKey)
	priv.p = privBls
	err := priv.p.Deserialize(privKey1)
	assert.NoError(t, err)

	pub := new(PublicKey)
	pubBls := new(bls12.PublicKey)
	pub.p = pubBls

	err = pub.p.Deserialize(pubKey1)
	assert.NoError(t, err)

	// This part confirms that bls generator point is retrieved and is static
	firstGenerator := new(bls12.PublicKey)
	err = firstGenerator.Deserialize(pubBls.Serialize())
	bls12.BlsGetGeneratorOfPublicKey(firstGenerator)
	assert.DeepEqual(t, generatorPubKey, firstGenerator.Serialize())

	msg := common2.BigToHash(big.NewInt(56)).Bytes()
	sig := priv.Sign(msg)

	// Assure that we work on the same set of values each time.
	assert.DeepEqual(t, hexSignature, sig.Marshal())

	assert.Equal(t, 96, len(sig.Marshal()))
	signature := sig.(*Signature)
	compressed := signature.Compress()
	assert.Equal(t, CompressedSize, len(compressed))
	assert.DeepEqual(t, true, sig.Verify(pub, msg))
	verified := VerifyCompressed(pub, msg, compressed)
	assert.Equal(t, true, verified)
}

func TestAggregateVerify(t *testing.T) {
	pubkeys := make([]common.PublicKey, 0, 100)
	sigs := make([]common.Signature, 0, 100)
	var msgs [][32]byte
	for i := 0; i < 100; i++ {
		msg := [32]byte{'h', 'e', 'l', 'l', 'o', byte(i)}
		priv, err := RandKey()
		require.NoError(t, err)
		pub := priv.PublicKey()
		sig := priv.Sign(msg[:])
		pubkeys = append(pubkeys, pub)
		sigs = append(sigs, sig)
		msgs = append(msgs, msg)
	}
	aggSig := Aggregate(sigs)
	assert.DeepEqual(t, true, aggSig.AggregateVerify(pubkeys, msgs))
}

func TestFastAggregateVerify(t *testing.T) {
	pubkeys := make([]common.PublicKey, 0, 100)
	sigs := make([]common.Signature, 0, 100)
	msg := [32]byte{'h', 'e', 'l', 'l', 'o'}
	for i := 0; i < 100; i++ {
		priv, err := RandKey()
		require.NoError(t, err)
		pub := priv.PublicKey()
		sig := priv.Sign(msg[:])
		pubkeys = append(pubkeys, pub)
		sigs = append(sigs, sig)
	}
	aggSig := AggregateSignatures(sigs)
	assert.DeepEqual(t, true, aggSig.FastAggregateVerify(pubkeys, msg))
}

func TestMultipleSignatureVerification(t *testing.T) {
	pubkeys := make([]common.PublicKey, 0, 100)
	sigs := make([]common.Signature, 0, 100)
	var msgs [][32]byte
	for i := 0; i < 100; i++ {
		msg := [32]byte{'h', 'e', 'l', 'l', 'o', byte(i)}
		priv, err := RandKey()
		require.NoError(t, err)
		pub := priv.PublicKey()
		sig := priv.Sign(msg[:])
		pubkeys = append(pubkeys, pub)
		sigs = append(sigs, sig)
		msgs = append(msgs, msg)
	}
	verify, err := VerifyMultipleSignatures(sigs, msgs, pubkeys)
	assert.NoError(t, err)
	assert.Equal(t, true, verify, "Signature did not verify")
}

func TestMultipleSignatureVerification_FailsCorrectly(t *testing.T) {
	pubkeys := make([]common.PublicKey, 0, 100)
	sigs := make([]common.Signature, 0, 100)
	var msgs [][32]byte
	for i := 0; i < 100; i++ {
		msg := [32]byte{'h', 'e', 'l', 'l', 'o', byte(i)}
		priv, err := RandKey()
		require.NoError(t, err)
		pub := priv.PublicKey()
		sig := priv.Sign(msg[:])
		pubkeys = append(pubkeys, pub)
		sigs = append(sigs, sig)
		msgs = append(msgs, msg)
	}
	// We mess with the last 2 signatures, where we modify their values
	// such that they wqould not fail in aggregate signature verification.
	lastSig := sigs[len(sigs)-1]
	secondLastSig := sigs[len(sigs)-2]
	// Convert to bls object
	rawSig := new(bls12.Sign)
	require.NoError(t, rawSig.Deserialize(secondLastSig.Marshal()))
	rawSig2 := new(bls12.Sign)
	require.NoError(t, rawSig2.Deserialize(lastSig.Marshal()))
	// set random field prime value
	fprime := new(bls12.Fp)
	fprime.SetInt64(100)

	// set random field prime value.
	fprime2 := new(bls12.Fp)
	fprime2.SetInt64(50)

	// make a combined fp2 object.
	fp2 := new(bls12.Fp2)
	fp2.D = [2]bls12.Fp{*fprime, *fprime2}

	g2Point := new(bls12.G2)
	require.NoError(t, bls12.MapToG2(g2Point, fp2))
	// We now add/subtract the respective g2 points by a fixed
	// value. This would cause singluar verification to fail but
	// not aggregate verification.
	firstG2 := bls12.CastFromSign(rawSig)
	secondG2 := bls12.CastFromSign(rawSig2)
	bls12.G2Add(firstG2, firstG2, g2Point)
	bls12.G2Sub(secondG2, secondG2, g2Point)

	lastSig, err := SignatureFromBytes(rawSig.Serialize())
	require.NoError(t, err)
	secondLastSig, err = SignatureFromBytes(rawSig2.Serialize())
	require.NoError(t, err)
	sigs[len(sigs)-1] = lastSig
	sigs[len(sigs)-2] = secondLastSig

	// This method is expected to pass, as it would not
	// be able to detect bad signatures
	aggSig := AggregateSignatures(sigs)
	if !aggSig.AggregateVerify(pubkeys, msgs) {
		t.Error("Signature did not verify")
	}
	// This method would be expected to fail.
	verify, err := VerifyMultipleSignatures(sigs, msgs, pubkeys)
	assert.NoError(t, err)
	assert.Equal(t, false, verify, "Signature verified when it was not supposed to")
}

func TestFastAggregateVerify_ReturnsFalseOnEmptyPubKeyList(t *testing.T) {
	var pubkeys []common.PublicKey
	msg := [32]byte{'h', 'e', 'l', 'l', 'o'}

	aggSig := NewAggregateSignature()
	if aggSig.FastAggregateVerify(pubkeys, msg) != false {
		t.Error("Expected FastAggregateVerify to return false with empty input " +
			"of public keys.")
	}
}

func TestSignatureFromBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		err   error
	}{
		{
			name: "Nil",
			err:  errors.New("signature must be 96 bytes"),
		},
		{
			name:  "Empty",
			input: []byte{},
			err:   errors.New("signature must be 96 bytes"),
		},
		{
			name:  "Short",
			input: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:   errors.New("signature must be 96 bytes"),
		},
		{
			name:  "Long",
			input: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:   errors.New("signature must be 96 bytes"),
		},
		{
			name:  "Bad",
			input: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:   errors.New("could not unmarshal bytes into signature: err blsSignatureDeserialize 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		},
		{
			name:  "Good",
			input: []byte{0xab, 0xb0, 0x12, 0x4c, 0x75, 0x74, 0xf2, 0x81, 0xa2, 0x93, 0xf4, 0x18, 0x5c, 0xad, 0x3c, 0xb2, 0x26, 0x81, 0xd5, 0x20, 0x91, 0x7c, 0xe4, 0x66, 0x65, 0x24, 0x3e, 0xac, 0xb0, 0x51, 0x00, 0x0d, 0x8b, 0xac, 0xf7, 0x5e, 0x14, 0x51, 0x87, 0x0c, 0xa6, 0xb3, 0xb9, 0xe6, 0xc9, 0xd4, 0x1a, 0x7b, 0x02, 0xea, 0xd2, 0x68, 0x5a, 0x84, 0x18, 0x8a, 0x4f, 0xaf, 0xd3, 0x82, 0x5d, 0xaf, 0x6a, 0x98, 0x96, 0x25, 0xd7, 0x19, 0xcc, 0xd2, 0xd8, 0x3a, 0x40, 0x10, 0x1f, 0x4a, 0x45, 0x3f, 0xca, 0x62, 0x87, 0x8c, 0x89, 0x0e, 0xca, 0x62, 0x23, 0x63, 0xf9, 0xdd, 0xb8, 0xf3, 0x67, 0xa9, 0x1e, 0x84},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := SignatureFromBytes(test.input)
			if test.err != nil {
				assert.ErrorContains(t, test.err.Error(), err)
			} else {
				assert.NoError(t, err)
				assert.DeepEqual(t, test.input, res.Marshal())
			}
		})
	}
}

func TestCopy(t *testing.T) {
	signatureA := &Signature{s: bls12.HashAndMapToSignature([]byte("foo"))}
	signatureB, ok := signatureA.Copy().(*Signature)
	require.Equal(t, true, ok)

	assert.NotEqual(t, signatureA, signatureB)
	assert.NotEqual(t, signatureA.s, signatureB.s)
	assert.DeepEqual(t, signatureA, signatureB)

	signatureA.s.Add(bls12.HashAndMapToSignature([]byte("bar")))
	assert.DeepNotEqual(t, signatureA, signatureB)
}
