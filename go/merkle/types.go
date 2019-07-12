package merkle

import (
	"crypto/sha512"

	"github.com/keybase/client/go/msgpack"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/client/go/sig3"
	merkletree "github.com/keybase/go-merkle-tree"
	"github.com/pkg/errors"
)

type TreeSeqno int64

type EncodingType byte

const (
	EncodingTypeBlindedSHA256v1     EncodingType = 1 // p = HMAC-SHA256; (k, v) -> (k, p(p(k, s), v)) where s is a secret unique per Merkle seqno
	EncodingTypeBlindedSHA512_256v1 EncodingType = 2 // p = HMAC-SHA512-256; (k, v) -> (k, p(p(k, s), v)) where s is a secret unique per Merkle seqno
)

const CurrentEncodingType = EncodingTypeBlindedSHA512_256v1

const MaxChildrenPerLeaf = 64

func GetTreeConfig(encodingType EncodingType) (merkletree.Config, error) {
	switch encodingType {
	case EncodingTypeBlindedSHA256v1:
		return merkletree.NewConfig(SHA256Hasher{}, 32, MaxChildrenPerLeaf, EncodedLeaf{}), nil
	case EncodingTypeBlindedSHA512_256v1:
		return merkletree.NewConfig(SHA512_256Hasher{}, 32, MaxChildrenPerLeaf, EncodedLeaf{}), nil
	}
	return merkletree.Config{}, errors.Errorf("unknown encoding type %q", encodingType)
}

type EncodedLeaf []byte

var _ merkletree.ValueConstructor = (*EncodedLeaf)(nil)

func (l EncodedLeaf) Construct() interface{} {
	return &[]byte{}
}

type LeafType uint16

const (
	LeafTypeChain17v1 = 1
)

type LeafContainer struct {
	_struct   bool     `codec:",toarray"`
	LeafType  LeafType // specifies structure of leafBytes
	LeafBytes []byte   // msgpack deserialization implements Leaf
}

func NewLeafContainer(leafType LeafType, leafBytes []byte) LeafContainer {
	return LeafContainer{LeafType: leafType, LeafBytes: leafBytes}
}

func (c LeafContainer) Serialize() ([]byte, error) {
	return msgpack.EncodeCanonical(c)
}

type Leaf interface {
	Serialize() ([]byte, error)
	Type() LeafType
	ID() []byte
	GetSeqno() keybase1.Seqno
}

type Chain17v1Leaf struct {
	_struct bool `codec:",toarray"`
	TeamID  sig3.TeamID
	SigID   []byte
	LinkID  sig3.LinkID
	Seqno   keybase1.Seqno
}

var _ Leaf = (*Chain17v1Leaf)(nil)

func (l Chain17v1Leaf) Serialize() ([]byte, error) {
	return msgpack.EncodeCanonical(l)
}

func (l Chain17v1Leaf) Type() LeafType {
	return LeafTypeChain17v1
}

func (l Chain17v1Leaf) ID() []byte {
	return l.TeamID[:]
}

func (l Chain17v1Leaf) GetSeqno() keybase1.Seqno {
	return l.Seqno
}

func ExportLeaf(l Leaf) (LeafContainer, error) {
	b, err := l.Serialize()
	if err != nil {
		return LeafContainer{}, errors.Wrap(err, "failed to serialize leaf")
	}
	return NewLeafContainer(l.Type(), b), nil
}

type Skips map[TreeSeqno][]byte

type RootMetadata struct {
	_struct      bool         `codec:",toarray"`
	EncodingType EncodingType `codec:"e"`
	Seqno        TreeSeqno    `codec:"s"`
	Skips        Skips        `codec:"t"` // includes prev
	RootHash     []byte       `codec:"r"`
}

func (r RootMetadata) EncodingAndHashMeta() (encoding []byte, hashMeta []byte, err error) {
	b, err := msgpack.EncodeCanonical(r)
	if err != nil {
		return nil, nil, err
	}
	h := sha512.Sum512_256(b)
	return b, h[:], nil
}

func (r RootMetadata) HashMeta() ([]byte, error) {
	_, hashMeta, err := r.EncodingAndHashMeta()
	return hashMeta, err
}

type Root struct {
	// No plain "Hash"; always HashMeta!
	Seqno        keybase1.Seqno
	Ctime        keybase1.Time
	HashMetadata []byte
	Metadata     []byte
}

type BlindedPreimage struct {
	LeafContainer  LeafContainer
	BlindedEntropy []byte
}

func NewBlindedPreimage(leaf Leaf, blindedEntropy []byte) (BlindedPreimage, error) {
	container, err := ExportLeaf(leaf)
	if err != nil {
		return BlindedPreimage{}, err
	}
	return BlindedPreimage{LeafContainer: container, BlindedEntropy: blindedEntropy}, nil
}

type Skiplist = []RootMetadata
type PathResponse struct {
	RootMetadata RootMetadata      `codec:"r,omitempty"`
	Path         []merkletree.Node `codec:"p,omitempty"`

	// BlindedPreimage underlies the hash that is actually in the merkle tree.
	BlindedPreimage BlindedPreimage `codec:"v,omitempty"`

	Skiplists []Skiplist `codec:"s,omitempty"`
}

type Key struct {
	Key []byte
}

func NewKey(key []byte) Key {
	return Key{Key: key}
}

type Secret struct {
	Secret []byte
}

func NewSecret(secret []byte) Secret {
	return Secret{Secret: secret}
}
