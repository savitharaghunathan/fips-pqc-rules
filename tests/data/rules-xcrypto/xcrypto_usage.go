package main

import (
	// Test: fips-go-crypto-00100 - MD4 (insecure)
	"golang.org/x/crypto/md4"

	// Test: fips-go-crypto-00101 - RIPEMD-160 (non-FIPS)
	"golang.org/x/crypto/ripemd160"

	// Test: fips-go-crypto-00200 - Blowfish (legacy)
	"golang.org/x/crypto/blowfish"

	// Test: fips-go-crypto-00201 - Twofish (non-FIPS)
	"golang.org/x/crypto/twofish"

	// Test: fips-go-crypto-00202 - CAST5 (legacy)
	"golang.org/x/crypto/cast5"

	// Test: fips-go-crypto-00203 - TEA (insecure)
	"golang.org/x/crypto/tea"

	// Test: fips-go-crypto-00204 - XTEA (insecure)
	"golang.org/x/crypto/xtea"

	// Test: fips-go-crypto-00300 - ChaCha20 (non-FIPS)
	"golang.org/x/crypto/chacha20"

	// Test: fips-go-crypto-00301 - Salsa20 (non-FIPS)
	"golang.org/x/crypto/salsa20"

	// Test: fips-go-crypto-00400 - ChaCha20-Poly1305 (non-FIPS)
	"golang.org/x/crypto/chacha20poly1305"

	// Test: fips-go-crypto-00401 - Poly1305 (non-FIPS)
	"golang.org/x/crypto/poly1305"

	// Test: fips-go-crypto-00500 - Curve25519 (non-FIPS)
	"golang.org/x/crypto/curve25519"

	// Test: fips-go-crypto-00600 - Blake2b (non-FIPS)
	"golang.org/x/crypto/blake2b"

	// Test: fips-go-crypto-00601 - Blake2s (non-FIPS)
	"golang.org/x/crypto/blake2s"

	// Test: fips-go-crypto-00602 - HKDF (bypasses FIPS module)
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"

	// Test: fips-go-crypto-00603 - SHA-3 (bypasses FIPS module)
	"golang.org/x/crypto/sha3"

	// Test: fips-go-crypto-00700 - Argon2 (non-FIPS)
	"golang.org/x/crypto/argon2"

	// Test: fips-go-crypto-00701 - bcrypt (non-FIPS)
	"golang.org/x/crypto/bcrypt"

	// Test: fips-go-crypto-00702 - scrypt (evaluate)
	"golang.org/x/crypto/scrypt"

	// Test: fips-go-crypto-00801 - NaCl box (non-FIPS)
	"golang.org/x/crypto/nacl/box"

	// Test: fips-go-crypto-00802 - NaCl secretbox (non-FIPS)
	"golang.org/x/crypto/nacl/secretbox"

	// Test: fips-go-crypto-00807 - SSH (requires analysis)
	"golang.org/x/crypto/ssh"
)

func useMD4() {
	h := md4.New()
	h.Write([]byte("data"))
}

func useRIPEMD160() {
	h := ripemd160.New()
	h.Write([]byte("data"))
}

func useBlowfish() {
	block, _ := blowfish.NewCipher([]byte("secretkey"))
	_ = block
}

func useTwofish() {
	block, _ := twofish.NewCipher(make([]byte, 16))
	_ = block
}

func useCAST5() {
	block, _ := cast5.NewCipher([]byte("secretkey"))
	_ = block
}

func useTEA() {
	block, _ := tea.NewCipher(make([]byte, 16))
	_ = block
}

func useXTEA() {
	block, _ := xtea.NewCipher(make([]byte, 16))
	_ = block
}

func useChaCha20() {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	cipher, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
	_ = cipher
}

func useSalsa20() {
	var out, in []byte
	var nonce [8]byte
	var key [32]byte
	salsa20.XORKeyStream(out, in, nonce[:], &key)
}

func useChaCha20Poly1305() {
	key := make([]byte, 32)
	aead, _ := chacha20poly1305.New(key)
	_ = aead
}

func usePoly1305() {
	var out [16]byte
	var key [32]byte
	poly1305.Sum(&out, []byte("message"), &key)
}

func useCurve25519() {
	var scalar, point [32]byte
	result, _ := curve25519.X25519(scalar[:], point[:])
	_ = result
}

func useBlake2b() {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("data"))
}

func useBlake2s() {
	h, _ := blake2s.New256(nil)
	h.Write([]byte("data"))
}

func useHKDF() {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")
	reader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, 32)
	reader.Read(key)
}

func useSHA3() {
	h := sha3.New256()
	h.Write([]byte("data"))
	_ = h.Sum(nil)
}

func useArgon2() {
	password := []byte("password")
	salt := make([]byte, 16)
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	_ = key
}

func useBcrypt() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_ = hash
}

func useScrypt() {
	key, _ := scrypt.Key([]byte("password"), []byte("salt"), 32768, 8, 1, 32)
	_ = key
}

func useNaClBox() {
	var nonce [24]byte
	var publicKey, privateKey [32]byte
	box.Seal(nil, []byte("message"), &nonce, &publicKey, &privateKey)
}

func useNaClSecretBox() {
	var nonce [24]byte
	var key [32]byte
	secretbox.Seal(nil, []byte("message"), &nonce, &key)
}

func useSSH() {
	config := &ssh.ClientConfig{}
	_ = config
}

func main() {}
