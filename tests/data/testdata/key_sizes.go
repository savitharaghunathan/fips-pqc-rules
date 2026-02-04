package main

import (
	"crypto/dsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

// Test: fips-go-keysize-00100 - Weak RSA key sizes
func weakRSAKeys() {
	// 512-bit RSA - trivially broken
	key512, _ := rsa.GenerateKey(rand.Reader, 512)
	_ = key512

	// 1024-bit RSA - deprecated
	key1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	_ = key1024

	// 1536-bit RSA - non-standard
	key1536, _ := rsa.GenerateKey(rand.Reader, 1536)
	_ = key1536
}

// Test: fips-go-keysize-00101 - RSA 2048-bit (minimum FIPS)
func rsa2048() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key
}

// Test: fips-go-keysize-00102 - RSA 3072+ bit (strong)
func rsaStrong() {
	key3072, _ := rsa.GenerateKey(rand.Reader, 3072)
	key4096, _ := rsa.GenerateKey(rand.Reader, 4096)
	_ = key3072
	_ = key4096
}

// Test: fips-go-keysize-00300 - ECDSA/ECDH curve selection
func ecdsaCurves() {
	p224 := elliptic.P224()
	p256 := elliptic.P256()
	p384 := elliptic.P384()
	p521 := elliptic.P521()
	_ = p224
	_ = p256
	_ = p384
	_ = p521
}

// Test: fips-go-keysize-00400 - DSA parameter generation
func dsaParams() {
	var params dsa.Parameters
	dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)
}

// Test: fips-go-keysize-00500 - PBKDF2 iteration count
func pbkdf2Usage() {
	password := []byte("password")
	salt := []byte("randomsalt123456")

	// Should use 600,000+ iterations for SHA-256
	key := pbkdf2.Key(password, salt, 100000, 32, sha256.New)
	_ = key
}


