package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/cipher"
	"crypto/aes"
)

// Test: fips-go-weak-00100 - DES usage
func useDES() {
	key := []byte("12345678")
	block, _ := des.NewCipher(key)
	_ = block
}

// Test: fips-go-weak-00101 - 3DES usage
func use3DES() {
	key := []byte("123456781234567812345678")
	block, _ := des.NewTripleDESCipher(key)
	_ = block
}

// Test: fips-go-weak-00102 - RC4 usage
func useRC4() {
	key := []byte("secretkey")
	c, _ := rc4.NewCipher(key)
	_ = c
}

// Test: fips-go-weak-00200 - MD5 usage
func useMD5() {
	h := md5.New()
	h.Write([]byte("data"))

	sum := md5.Sum([]byte("data"))
	_ = sum
}

// Test: fips-go-weak-00201 - SHA1 usage
func useSHA1() {
	h := sha1.New()
	h.Write([]byte("data"))

	sum := sha1.Sum([]byte("data"))
	_ = sum
}

// Test: fips-go-weak-00301 - CBC mode usage
func useCBC() {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)

	iv := make([]byte, 16)
	encrypter := cipher.NewCBCEncrypter(block, iv)
	decrypter := cipher.NewCBCDecrypter(block, iv)
	_ = encrypter
	_ = decrypter
}

// Test: fips-go-weak-00302 - CFB/OFB/CTR modes
func useStreamModes() {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)

	cfbEnc := cipher.NewCFBEncrypter(block, iv)
	cfbDec := cipher.NewCFBDecrypter(block, iv)
	ofb := cipher.NewOFB(block, iv)
	ctr := cipher.NewCTR(block, iv)

	_ = cfbEnc
	_ = cfbDec
	_ = ofb
	_ = ctr
}

func main() {}
