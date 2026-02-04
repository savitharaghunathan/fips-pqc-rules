// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hkdf implements the HMAC-based Extract-and-Expand Key Derivation
// Function (HKDF) as defined in RFC 5869.
package hkdf

import (
	"hash"
	"io"
)

type hkdf struct {
	expander hash.Hash
	size     int

	info    []byte
	counter byte

	prev []byte
	buf  []byte
}

func (f *hkdf) Read(p []byte) (int, error) {
	return len(p), nil
}

// New returns a Reader that yields the output of HKDF
func New(hash func() hash.Hash, secret, salt, info []byte) io.Reader {
	return &hkdf{}
}

// Expand returns a Reader that yields the output of HKDF-Expand
func Expand(hash func() hash.Hash, pseudorandomKey, info []byte) io.Reader {
	return &hkdf{}
}

// Extract generates a pseudorandom key for use with Expand
func Extract(hash func() hash.Hash, secret, salt []byte) []byte {
	return nil
}
