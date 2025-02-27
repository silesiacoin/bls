package herumi

import (
	"fmt"
	bls12 "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/minio/sha256-simd"
	"github.com/pkg/errors"
	"github.com/silesiacoin/bls/bytesutil"
	"github.com/silesiacoin/bls/common"
	"github.com/silesiacoin/bls/rand"
	"os"
	vbls "vuvuzela.io/crypto/bls"
)

const CompressedSize = 32

// Signature used in the BLS signature scheme.
type Signature struct {
	s *bls12.Sign
}

func Sign(privateKey *vbls.PrivateKey, message []byte) vbls.Signature {
	return vbls.Sign(privateKey, message)
}

// SignatureFromBytes creates a BLS signature from a LittleEndian byte slice.
func SignatureFromBytes(sig []byte) (common.Signature, error) {
	if "true" == os.Getenv("SKIP_BLS_VERIFY") {
		return &Signature{}, nil
	}
	if len(sig) != 96 {
		return nil, fmt.Errorf("signature must be %d bytes", 96)
	}
	signature := &bls12.Sign{}
	err := signature.Deserialize(sig)
	if err != nil {
		return nil, errors.Wrap(err, "could not unmarshal bytes into signature")
	}
	return &Signature{s: signature}, nil
}

// Verify a bls signature given a public key, a message.
//
// In IETF draft BLS specification:
// Verify(PK, message, signature) -> VALID or INVALID: a verification
//      algorithm that outputs VALID if signature is a valid signature of
//      message under public key PK, and INVALID otherwise.
//
// In ETH2.0 specification:
// def Verify(PK: BLSPubkey, message: Bytes, signature: BLSSignature) -> bool
func (s *Signature) Verify(pubKey common.PublicKey, msg []byte) bool {
	if "true" == os.Getenv("SKIP_BLS_VERIFY") {
		return true
	}
	// Reject infinite public keys.
	if pubKey.(*PublicKey).p.IsZero() {
		return false
	}
	return s.s.VerifyByte(pubKey.(*PublicKey).p, msg)
}

// AggregateVerify verifies each public key against its respective message.
// This is vulnerable to rogue public-key attack. Each user must
// provide a proof-of-knowledge of the public key.
//
// In IETF draft BLS specification:
// AggregateVerify((PK_1, message_1), ..., (PK_n, message_n),
//      signature) -> VALID or INVALID: an aggregate verification
//      algorithm that outputs VALID if signature is a valid aggregated
//      signature for a collection of public keys and messages, and
//      outputs INVALID otherwise.
//
// In ETH2.0 specification:
// def AggregateVerify(pairs: Sequence[PK: BLSPubkey, message: Bytes], signature: BLSSignature) -> boo
func (s *Signature) AggregateVerify(pubKeys []common.PublicKey, msgs [][32]byte) bool {
	if "true" == os.Getenv("SKIP_BLS_VERIFY") {
		return true
	}
	size := len(pubKeys)
	if size == 0 {
		return false
	}
	if size != len(msgs) {
		return false
	}
	msgSlices := make([]byte, 0, 32*len(msgs))
	rawKeys := make([]bls12.PublicKey, 0, len(pubKeys))
	for i := 0; i < size; i++ {
		msgSlices = append(msgSlices, msgs[i][:]...)
		rawKeys = append(rawKeys, *(pubKeys[i].(*PublicKey).p))
	}
	// Use "NoCheck" because we do not care if the messages are unique or not.
	return s.s.AggregateVerifyNoCheck(rawKeys, msgSlices)
}

// FastAggregateVerify verifies all the provided public keys with their aggregated signature.
//
// In IETF draft BLS specification:
// FastAggregateVerify(PK_1, ..., PK_n, message, signature) -> VALID
//      or INVALID: a verification algorithm for the aggregate of multiple
//      signatures on the same message.  This function is faster than
//      AggregateVerify.
//
// In ETH2.0 specification:
// def FastAggregateVerify(PKs: Sequence[BLSPubkey], message: Bytes, signature: BLSSignature) -> bool
func (s *Signature) FastAggregateVerify(pubKeys []common.PublicKey, msg [32]byte) bool {
	if "true" == os.Getenv("SKIP_BLS_VERIFY") {
		return true
	}
	if len(pubKeys) == 0 {
		return false
	}
	rawKeys := make([]bls12.PublicKey, len(pubKeys))
	for i := 0; i < len(pubKeys); i++ {
		rawKeys[i] = *(pubKeys[i].(*PublicKey).p)
	}

	return s.s.FastAggregateVerify(rawKeys, msg[:])
}

// NewAggregateSignature creates a blank aggregate signature.
func NewAggregateSignature() common.Signature {
	return &Signature{s: bls12.HashAndMapToSignature([]byte{'m', 'o', 'c', 'k'})}
}

// AggregateSignatures converts a list of signatures into a single, aggregated sig.
func AggregateSignatures(sigs []common.Signature) common.Signature {
	if len(sigs) == 0 {
		return nil
	}
	if "true" == os.Getenv("SKIP_BLS_VERIFY") {
		return sigs[0]
	}

	signature := *sigs[0].Copy().(*Signature).s
	for i := 1; i < len(sigs); i++ {
		signature.Add(sigs[i].(*Signature).s)
	}
	return &Signature{s: &signature}
}

// Aggregate is an alias for AggregateSignatures, defined to conform to BLS specification.
//
// In IETF draft BLS specification:
// Aggregate(signature_1, ..., signature_n) -> signature: an
//      aggregation algorithm that compresses a collection of signatures
//      into a single signature.
//
// In ETH2.0 specification:
// def Aggregate(signatures: Sequence[BLSSignature]) -> BLSSignature
//
// Deprecated: Use AggregateSignatures.
func Aggregate(sigs []common.Signature) common.Signature {
	return AggregateSignatures(sigs)
}

func (s Signature) Compress() *[CompressedSize]byte {
	// only keep the x-coordinate
	var compressed [CompressedSize]byte
	compressedBytes := s.Marshal()
	copy(compressed[:], compressedBytes[0:32])
	return &compressed
}

// VerifyCompressed verifies a compressed aggregate signature.  Returns
// false if messages are not distinct.
// TODO: try to use PublicKey from herumi to achieve this
func VerifyCompressed(keys []*vbls.PublicKey, messages [][]byte, sig *[CompressedSize]byte) bool {
	return vbls.VerifyCompressed(keys, messages, sig)
}

// VerifyMultipleSignatures verifies a non-singular set of signatures and its respective pubkeys and messages.
// This method provides a safe way to verify multiple signatures at once. We pick a number randomly from 1 to max
// uint64 and then multiply the signature by it. We continue doing this for all signatures and its respective pubkeys.
// S* = S_1 * r_1 + S_2 * r_2 + ... + S_n * r_n
// P'_{i,j} = P_{i,j} * r_i
// e(S*, G) = \prod_{i=1}^n \prod_{j=1}^{m_i} e(P'_{i,j}, M_{i,j})
// Using this we can verify multiple signatures safely.
func VerifyMultipleSignatures(sigs []common.Signature, msgs [][32]byte, pubKeys []common.PublicKey) (bool, error) {
	if "true" == os.Getenv("SKIP_BLS_VERIFY") {
		return true, nil
	}
	if len(sigs) == 0 || len(pubKeys) == 0 {
		return false, nil
	}
	length := len(sigs)
	if length != len(pubKeys) || length != len(msgs) {
		return false, errors.Errorf("provided signatures, pubkeys and messages have differing lengths. S: %d, P: %d,M %d",
			length, len(pubKeys), len(msgs))
	}
	// Use a secure source of RNG.
	newGen := rand.NewGenerator()
	randNums := make([]bls12.Fr, length)
	signatures := make([]bls12.G2, length)
	msgSlices := make([]byte, 0, 32*len(msgs))
	for i := 0; i < len(sigs); i++ {
		rNum := newGen.Uint64()
		if err := randNums[i].SetLittleEndian(bytesutil.Bytes8(rNum)); err != nil {
			return false, err
		}
		// Cast signature to a G2 value
		signatures[i] = *bls12.CastFromSign(sigs[i].(*Signature).s)

		// Flatten message to single byte slice to make it compatible with herumi.
		msgSlices = append(msgSlices, msgs[i][:]...)
	}
	// Perform multi scalar multiplication on all the relevant G2 points
	// with our generated random numbers.
	finalSig := new(bls12.G2)
	bls12.G2MulVec(finalSig, signatures, randNums)

	multiKeys := make([]bls12.PublicKey, length)
	for i := 0; i < len(pubKeys); i++ {
		if pubKeys[i] == nil {
			return false, errors.New("nil public key")
		}
		// Perform scalar multiplication for the corresponding g1 points.
		g1 := new(bls12.G1)
		bls12.G1Mul(g1, bls12.CastFromPublicKey(pubKeys[i].(*PublicKey).p), &randNums[i])
		multiKeys[i] = *bls12.CastToPublicKey(g1)
	}
	aggSig := bls12.CastToSign(finalSig)

	return aggSig.AggregateVerifyNoCheck(multiKeys, msgSlices), nil
}

// Marshal a signature into a LittleEndian byte slice.
func (s *Signature) Marshal() []byte {
	if "true" == os.Getenv("SKIP_BLS_VERIFY") {
		return make([]byte, 96)
	}

	return s.s.Serialize()
}

// Copy returns a full deep copy of a signature.
func (s *Signature) Copy() common.Signature {
	sign := *s.s
	return &Signature{s: &sign}
}

func distinct(msgs [][]byte) bool {
	m := make(map[[32]byte]bool)
	for _, msg := range msgs {
		h := sha256.Sum256(msg)
		if m[h] {
			return false
		}
		m[h] = true
	}
	return true
}
