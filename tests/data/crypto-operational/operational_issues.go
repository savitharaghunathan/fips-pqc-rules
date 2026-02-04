package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	mathrand "math/rand"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Test: fips-go-ops-00100 - Hardcoded cryptographic key
func hardcodedKey() {
	// Hardcoded AES key - CRITICAL VULNERABILITY
	block, _ := aes.NewCipher([]byte("mysecretkey12345"))
	_ = block

	// Hardcoded HMAC key
	mac := hmac.New(sha256.New, []byte("hmac-secret-key!"))
	_ = mac
}

// Test: fips-go-ops-00101 - Hardcoded IV/Nonce
func hardcodedIV() {
	key := make([]byte, 16)
	rand.Read(key)
	block, _ := aes.NewCipher(key)

	// Hardcoded IV - CRITICAL VULNERABILITY
	encrypter := cipher.NewCBCEncrypter(block, []byte("1234567890123456"))
	decrypter := cipher.NewCBCDecrypter(block, []byte("1234567890123456"))
	_ = encrypter
	_ = decrypter

	// Hardcoded IV in CFB mode
	cfb := cipher.NewCFBEncrypter(block, []byte("staticivvalue!!!"))
	_ = cfb

	// Hardcoded IV in OFB mode
	ofb := cipher.NewOFB(block, []byte("staticivvalue!!!"))
	_ = ofb

	// Hardcoded IV in CTR mode
	ctr := cipher.NewCTR(block, []byte("staticivvalue!!!"))
	_ = ctr
}

// Test: fips-go-ops-00200 - math/rand used (not cryptographically secure)
func weakRandom() {
	// math/rand is predictable - NOT for crypto
	mathrand.Seed(12345)
	value := mathrand.Int()
	_ = value

	source := mathrand.NewSource(42)
	_ = source
}

// Test: fips-go-ops-00201 - crypto/rand usage (correct)
func strongRandom() {
	key := make([]byte, 32)
	rand.Read(key)

	iv := make([]byte, 16)
	io.ReadFull(rand.Reader, iv)
}

// Test: fips-go-ops-00300 - Static salt in password hashing
func staticSalt() {
	password := []byte("userpassword")

	// Static salt - VULNERABILITY
	key1 := pbkdf2.Key(password, []byte("static-salt-bad!"), 600000, 32, sha256.New)
	_ = key1

	// Static salt in scrypt
	key2, _ := scrypt.Key(password, []byte("static-salt-bad!"), 32768, 8, 1, 32)
	_ = key2

	// Static salt in argon2
	key3 := argon2.IDKey(password, []byte("static-salt-bad!"), 1, 64*1024, 4, 32)
	_ = key3
}

// Test: fips-go-ops-00400 - GCM nonce (requires review)
func gcmUsage() {
	key := make([]byte, 32)
	rand.Read(key)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	plaintext := []byte("secret data")
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	_ = ciphertext
}

func main() {}
