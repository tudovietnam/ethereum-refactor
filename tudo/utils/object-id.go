/**
 * Written by Vy Nguyen (2018)
 */
package utils

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	Sha1Len = 20
)

type ObjectId [Sha1Len]byte

// Equals returns true when two ObjectId are the same.
//
func (o ObjectId) Equals(that ObjectId) bool {
	if (o == that) || bytes.Compare(o[:], that[:]) == 0 {
		return true
	}
	return false
}

// EncodeRLP encodes the object id to a write stream.
//
func (o ObjectId) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, o)
}

// DecodeRLP decodes the stream back to object id.
//
func DecodeRLP(s *rlp.Stream, o ObjectId) error {
	origin, err := s.Raw()
	if err == nil {
		err = rlp.DecodeBytes(origin, o)
	}
	return err
}

// FromHash converts sha3-hash to object id format.
//
func FromHash(hash common.Hash) ObjectId {
	o := ObjectId{}
	copy(o[:], hash[0:Sha1Len])
	return o
}

// FromBytes converts a byte stream to object id.
//
func FromBytes(b []byte) ObjectId {
	o := ObjectId{}
	copy(o[:], b[:Sha1Len])
	return o
}

// HexToHash converts a string of hex to object id.
//
func HexToHash(s string) ObjectId {
	return FromBytes(common.FromHex(s))
}

// Hex converts object id into hex string.
//
func (o ObjectId) Hex() string {
	return hexutil.Encode(o[:])
}

// ToHash converts the object id back to hash.
//
func (o ObjectId) ToHash() common.Hash {
	h := common.Hash{}
	copy(h[0:Sha1Len], o[:])
	return h
}

// ToHex convert a byte array to hex string without leading 0x
//
func ToHex(b []byte) string {
	hex := common.Bytes2Hex(b)
	if len(hex) == 0 {
		return "0"
	}
	return hex
}

// ToPath converts object id to path spliting the hex string for optimized query lookup.
//
func (o ObjectId) ToPath(base string,
	dirLvl, hexChar int, mkdirs bool) (string, error) {
	return byte2Path(o[:], base, dirLvl, hexChar, mkdirs)
}

// Hash2Path converts hash to path spliting the hex string for optimized query lookup.
//
func Hash2Path(hash common.Hash, base string,
	dirLvl, hexChar int, mkdirs bool) (string, error) {
	return byte2Path(hash[:], base, dirLvl, hexChar, mkdirs)
}

func byte2Path(hash []byte, base string,
	dirLvl, hexChar int, mkdirs bool) (string, error) {
	var err error = nil
	start := 0
	for ; dirLvl > 0; dirLvl-- {
		end := hexChar + start
		base = filepath.Join(base, ToHex(hash[start:end]))
		start = end
	}
	if mkdirs == true {
		err = os.MkdirAll(base, 0700)
	}
	return filepath.Join(base, ToHex(hash[start:])), err
}

// FromPath converts the path above back to object id, or hash depending on the length.
//
func FromPath(base, path string) (*ObjectId, *common.Hash) {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return nil, nil
	}
	id := strings.Replace(rel, "/", "", -1)
	if len(id) == (Sha1Len * 2) {
		oid := HexToHash(id)
		return &oid, nil
	}
	h := common.Hash{}
	copy(h[:], id[:common.HashLength])
	return nil, &h
}
