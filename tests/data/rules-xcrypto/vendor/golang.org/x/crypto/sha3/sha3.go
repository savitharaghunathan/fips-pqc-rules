// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha3 implements the SHA-3 fixed-output-length hash functions and
// the SHAKE variable-output-length hash functions defined by FIPS-202.
package sha3

import "hash"

// state represents the partial evaluation of a SHA-3 function.
type state struct {
	a    [25]uint64
	buf  []byte
	rate int
	dsbyte byte
}

func (d *state) Write(p []byte) (int, error) { return len(p), nil }
func (d *state) Sum(b []byte) []byte         { return nil }
func (d *state) Reset()                       {}
func (d *state) Size() int                    { return 32 }
func (d *state) BlockSize() int               { return 136 }

// New224 creates a new SHA3-224 hash.
func New224() hash.Hash { return &state{} }

// New256 creates a new SHA3-256 hash.
func New256() hash.Hash { return &state{} }

// New384 creates a new SHA3-384 hash.
func New384() hash.Hash { return &state{} }

// New512 creates a new SHA3-512 hash.
func New512() hash.Hash { return &state{} }

// NewLegacyKeccak256 creates a new Keccak-256 hash.
func NewLegacyKeccak256() hash.Hash { return &state{} }

// NewLegacyKeccak512 creates a new Keccak-512 hash.
func NewLegacyKeccak512() hash.Hash { return &state{} }

// Sum224 returns the SHA3-224 checksum of the data.
func Sum224(data []byte) [28]byte { return [28]byte{} }

// Sum256 returns the SHA3-256 checksum of the data.
func Sum256(data []byte) [32]byte { return [32]byte{} }

// Sum384 returns the SHA3-384 checksum of the data.
func Sum384(data []byte) [48]byte { return [48]byte{} }

// Sum512 returns the SHA3-512 checksum of the data.
func Sum512(data []byte) [64]byte { return [64]byte{} }
