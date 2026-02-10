# FIPS 140 & PQC Compliance Rules for Go Cryptography

Static analysis rules for [Konveyor](https://www.konveyor.io/) that detect non-FIPS 140 compliant cryptographic usage in Go applications and inventory quantum-vulnerable algorithms for post-quantum cryptography (PQC) migration planning.

## Overview

This ruleset helps organizations:

- **Achieve FIPS 140 Compliance**: Detect usage of non-FIPS approved algorithms from `golang.org/x/crypto` and other sources
- **Plan PQC Migration**: Inventory cryptographic usage vulnerable to quantum computing attacks
- **Improve Security Posture**: Identify weak algorithms, insecure TLS configurations, and insufficient key sizes
- **Ensure Crypto Agility**: Detect hardcoded configurations that prevent algorithm rotation
- **Prepare for Go 1.24+**: Identify BoringCrypto/GOFIPS usage that should migrate to native FIPS mode

## Prerequisites

- [Konveyor Analyzer (kantra)](https://github.com/konveyor/kantra) CLI tool
- Go source code to analyze

## Quick Start

```bash
# Clone the rules
git clone <repository-url>
cd fips-pqc-rules

# Analyze a Go project
kantra analyze \
  --input /path/to/go-project \
  --output ./analysis-output \
  --rules .
```

## Rule Summary

**112 total rules** across 15 YAML files

| Category | Rules | Description |
|----------|-------|-------------|
| Core Rules | 86 | Production-ready compliance checks |
| Experimental Rules | 26 | Emerging patterns and Go 1.24+ features |

## Core Rules (86 rules)

| File | Rules | Description | Focus |
|------|-------|-------------|-------|
| `fips-xcrypto.yaml` | 34 | Core FIPS 140 rules for x/crypto packages | Non-FIPS algorithms (ChaCha20, Curve25519, Blake2, NaCl, etc.) |
| `tls-rules.yaml` | 14 | TLS configuration analysis | InsecureSkipVerify, version pinning, cipher agility |
| `pqc-inventory.yaml` | 9 | Quantum-vulnerable algorithm inventory | RSA, ECDSA, ECDH, DH, hash/AES quantum assessment |
| `pqc-jwt-signatures.yaml` | 8 | JWT/JWS/OAuth/OIDC signature detection | RS256, PS256, ES256, EdDSA, HS256, X.509, SSH keys |
| `crypto-weak-algorithms.yaml` | 7 | Weak/broken algorithm detection | DES, 3DES, RC4, MD5, SHA-1, CBC/CFB modes |
| `crypto-key-strength.yaml` | 7 | Key size and parameter validation | RSA < 2048, P-224 deprecated, ECC curves, DH parameters, PBKDF2 iterations |
| `crypto-operational.yaml` | 6 | Operational security patterns | Hardcoded keys/IVs, math/rand and math/rand/v2 misuse, static salts, AEAD nonces |
| `pqc-go-version.yaml` | 1 | Go version PQC readiness | Go 1.24+ required for native ML-KEM support |

## Experimental Rules (26 rules)

Located in the `experimental/` directory for emerging patterns and Go 1.24+ features:

| File | Rules | Description |
|------|-------|-------------|
| `fips-cipher-suites.yaml` | 6 | TLS cipher suite analysis (RC4, 3DES, CBC, RSA key exchange, TLS 1.3, ChaCha20) |
| `fips-tls-versions.yaml` | 4 | TLS version compliance (TLS 1.0/1.1 deprecated, SSL 3.0 banned, TLS 1.2 max blocking) |
| `pqc-hybrid-keyexchange.yaml` | 4 | Hybrid PQC key exchange (X25519MLKEM768, SecP256r1MLKEM768, crypto/mlkem, legacy Kyber draft) |
| `pqc-thirdparty.yaml` | 4 | Third-party PQC libraries (Cloudflare CIRCL, Kyber, Dilithium, hybrid schemes) |
| `pqc-boringcrypto.yaml` | 3 | Legacy FIPS modes (GOEXPERIMENT=boringcrypto, golang-fips/go fork, GOFIPS=1) |
| `pqc-godebug.yaml` | 3 | GODEBUG settings (tlsmlkem=0 disables PQC, legacy tlskyber, fips140=on/only) |
| `pqc-tls-curvepreferences.yaml` | 2 | TLS curve preferences that may block PQC key exchange |

## Rule Metadata

### Categories

| Category | Meaning |
|----------|---------|
| `mandatory` | Must be fixed for FIPS 140 compliance |
| `potential` | May require action depending on context |


### FIPS 140 Compliance Tags

| Tag | Meaning |
|-----|---------|
| `FIPS-140=Unacceptable` | Algorithm is banned or not NIST-approved |
| `FIPS-140=Acceptable-Evaluate` | May be acceptable, requires context review |
| `FIPS-140=Requires-Analysis` | High-level protocol, algorithm usage varies |
| `FIPS-140=Deprecated` | Being phased out (e.g., BoringCrypto, P-224) |
| `FIPS-140=Acceptable` | FIPS approved and recommended (e.g., ML-KEM) |
| `FIPS-140=Enabled` | FIPS mode is active |
| `FIPS-140=Not-Approved` | Algorithm secure but not FIPS validated |

### PQC Migration Tags

| Tag | Meaning |
|-----|---------|
| `PQC=Migration-Required` | Algorithm vulnerable to quantum attacks |
| `PQC=Acceptable` | Algorithm provides adequate quantum security |
| `PQC=Blocking` | Configuration blocks PQC adoption |
| `PQC=Hybrid` | Using hybrid classical+PQC scheme |
| `PQC=Native` | Using Go stdlib PQC (crypto/mlkem) |
| `PQC=Third-Party` | Using external PQC library |
| `PQC=Legacy-Draft` | Using pre-standardization PQC |
| `PQC=Disabled` | PQC explicitly disabled |
| `Quantum=Vulnerable` | Broken by Shor's algorithm |
| `Quantum=Resistant` | Secure against known quantum attacks |
| `Quantum=Protected` | Using PQC or hybrid protection |

### CWE Tags

Rules include relevant [Common Weakness Enumeration](https://cwe.mitre.org/) identifiers:

| CWE | Description | Used For |
|-----|-------------|----------|
| `CWE-295` | Improper Certificate Validation | InsecureSkipVerify, custom cert verification, gRPC/K8s insecure, empty ServerName |
| `CWE-319` | Cleartext Transmission of Sensitive Information | Plain HTTP, database TLS disabled |
| `CWE-323` | Reusing a Nonce, Key Pair in Encryption | GCM/AEAD nonce reuse |
| `CWE-326` | Inadequate Encryption Strength | Weak RSA keys, P-224 curve, TLS 1.0/1.1, RSA key exchange without PFS |
| `CWE-327` | Use of Broken or Risky Cryptographic Algorithm | DES, 3DES, RC4, CBC/CFB/OFB/CTR unauthenticated modes, SSL 3.0 |
| `CWE-328` | Use of Weak Hash | MD5, SHA-1 |
| `CWE-330` | Use of Insufficiently Random Values | Hardcoded IVs/nonces, crypto/rand verification |
| `CWE-338` | Use of Cryptographically Weak PRNG | math/rand, math/rand/v2 |
| `CWE-757` | Selection of Less-Secure Algorithm During Negotiation | Hardcoded MaxVersion/MinVersion/CipherSuites, custom TLS configs |
| `CWE-760` | Use of a One-Way Hash with a Predictable Salt | Static salts in PBKDF2/scrypt/Argon2 |
| `CWE-798` | Use of Hard-coded Credentials | Hardcoded encryption keys |

## Detected Patterns

### Non-FIPS Algorithms from x/crypto

| Package | Status | FIPS Alternative |
|---------|--------|------------------|
| `chacha20`, `chacha20poly1305` | Unacceptable | `crypto/aes` + GCM |
| `salsa20` | Unacceptable | `crypto/aes` + GCM |
| `curve25519` | Unacceptable | `crypto/ecdh` (P-256/P-384) |
| `blake2b`, `blake2s` | Unacceptable | `crypto/sha256`, `crypto/sha512` |
| `argon2`, `bcrypt` | Unacceptable | `crypto/pbkdf2` (Go 1.24+), `x/crypto/pbkdf2` |
| `blowfish`, `twofish`, `cast5` | Unacceptable | `crypto/aes` |
| `tea`, `xtea` | Unacceptable | `crypto/aes` |
| `md4`, `ripemd160` | Unacceptable | `crypto/sha256` |
| `nacl/box`, `nacl/secretbox` | Unacceptable | `crypto/aes` + GCM, `crypto/ecdh` |
| `nacl/sign`, `nacl/auth` | Unacceptable | `crypto/ed25519`, `crypto/hmac` |
| `poly1305` | Unacceptable | `crypto/hmac` or AES-GCM |
| `bn256` | Unacceptable | `crypto/elliptic` (NIST curves) |
| `otr` | Unacceptable | `crypto/tls` |
| `hkdf` (x/crypto) | Evaluate | `crypto/hkdf` (Go 1.24+) |
| `sha3` (x/crypto) | Evaluate | `crypto/sha3` (Go 1.24+) |
| `ed25519` (x/crypto) | Evaluate | `crypto/ed25519` |
| `scrypt` | Evaluate | `crypto/pbkdf2` (Go 1.24+), `x/crypto/pbkdf2` |
| `xts` | Evaluate | FIPS validated XTS or AES-GCM |
| `ssh` | Requires Analysis | Configure FIPS cipher suites |
| `openpgp` | Requires Analysis | Review algorithm selection |
| `acme`, `ocsp`, `pkcs12` | Requires Analysis | Review crypto operations |
| `cryptobyte`, `x509roots` | Requires Analysis | Review consuming code |

### Weak Algorithms (Standard Library)

| Pattern | Issue | Alternative |
|---------|-------|-------------|
| `crypto/des` | Broken (56-bit key) | `crypto/aes` |
| `des.NewTripleDESCipher` | Deprecated (Sweet32) | `crypto/aes` |
| `crypto/rc4` | Broken (multiple attacks) | `crypto/aes` |
| `crypto/md5` | Broken (collisions) | `crypto/sha256` |
| `crypto/sha1` | Deprecated (collisions) | `crypto/sha256` |
| `cipher.NewCBC*` | Unauthenticated mode | `cipher.NewGCM` |
| `cipher.NewCFB*`, `NewOFB`, `NewCTR` | Unauthenticated modes | `cipher.NewGCM` |

### Key Size Issues

| Pattern | Issue | Requirement |
|---------|-------|-------------|
| `rsa.GenerateKey(_, 512)` | Trivially broken | Minimum 2048 bits |
| `rsa.GenerateKey(_, 1024)` | Deprecated since 2013 | Minimum 2048 bits |
| `rsa.GenerateKey(_, 1536)` | Non-standard | Minimum 2048 bits |
| `elliptic.P224()` | Deprecated (SP 800-186), 112-bit security | Use P-256 or higher |
| `pbkdf2.Key` | Check iterations | 600,000+ for SHA-256 |

### Operational Security Issues

| Pattern | Issue |
|---------|-------|
| `aes.NewCipher([]byte("..."))` | Hardcoded encryption key |
| `cipher.NewCBCEncrypter(_, []byte("..."))` | Hardcoded IV/nonce |
| `cipher.NewGCM` with static nonce | Nonce reuse vulnerability |
| `math/rand`, `math/rand/v2` for crypto | Predictable randomness |
| `pbkdf2.Key(_, []byte("..."))` | Static salt |

### TLS Configuration Issues

| Pattern | Issue | Risk |
|---------|-------|------|
| `InsecureSkipVerify: true` | Disables cert validation | MITM attacks |
| `MaxVersion: tls.VersionTLS12` | Blocks TLS 1.3 | Prevents PQC |
| `MinVersion: tls.VersionTLS10` | Allows deprecated TLS | Protocol attacks |
| `CipherSuites: [...]` | Hardcoded ciphers | Blocks rotation |
| `CurvePreferences: [...]` | Hardcoded curves | Blocks PQC curves |
| `VerifyPeerCertificate: func(...)` | Custom verification may bypass validation | MITM attacks |
| `grpc.WithInsecure()` | No TLS | No encryption |
| `sslmode=disable` | Database TLS disabled | Data exposure |
| `.ServerName = ""` | Hostname bypass | Cert substitution |

### TLS Cipher Suite Issues (Experimental)

| Cipher Suite | Issue |
|--------------|-------|
| `TLS_*_RC4_*` | RC4 banned (RFC 7465) |
| `TLS_*_3DES_*` | 3DES deprecated (Sweet32) |
| `TLS_*_CBC_*` | CBC vulnerable (Lucky13) |
| `TLS_RSA_WITH_*` | No forward secrecy |
| `TLS_CHACHA20_POLY1305_*` | Not FIPS approved |

### PQC Inventory (Quantum-Vulnerable)

These algorithms are currently FIPS-approved but require migration planning:

| Algorithm | Quantum Attack | NIST PQC Replacement |
|-----------|----------------|----------------------|
| RSA (all sizes) | Shor's algorithm | ML-KEM (FIPS 203), ML-DSA (FIPS 204) |
| ECDSA | Shor's algorithm | ML-DSA (FIPS 204), SLH-DSA (FIPS 205) |
| ECDH | Shor's algorithm | ML-KEM (FIPS 203) |
| DH | Shor's algorithm | ML-KEM (FIPS 203) |
| DSA | Shor's algorithm | ML-DSA (FIPS 204) |
| Ed25519 | Shor's algorithm | ML-DSA (FIPS 204) |

### PQC-Ready Algorithms (Quantum-Resistant)

| Algorithm | Quantum Security | Notes |
|-----------|------------------|-------|
| AES-256 | 128-bit post-quantum | Grover's algorithm halves effective key size |
| SHA-256 | ~85-bit quantum collision resistance | BHT algorithm provides cube-root speedup |
| SHA-512 | ~170-bit quantum collision resistance | Extra margin for preimage and collision |
| HMAC-SHA256+ | Quantum resistant | Symmetric, no Shor vulnerability |
| ML-KEM (Kyber) | FIPS 203 standardized | Go 1.24+ crypto/mlkem |
| X25519MLKEM768 | Hybrid classical+PQC | Go 1.24+ default in TLS |

## Go 1.24+ Features

### Native FIPS 140-3 Mode

Go 1.24 introduces native FIPS 140 support with a validated cryptographic module:

```bash
# Enable at runtime via GODEBUG
GODEBUG=fips140=on ./myapp

# Strict mode (panics on non-FIPS algorithms)
GODEBUG=fips140=only ./myapp
```

### Native ML-KEM (Post-Quantum)

```go
import "crypto/mlkem"

// ML-KEM-768 (recommended)
dk, ek := mlkem.GenerateKey768()

// Encapsulate (sender)
ciphertext, sharedSecret := ek.Encapsulate()

// Decapsulate (receiver)
sharedSecret := dk.Decapsulate(ciphertext)
```

### Hybrid TLS Key Exchange

Go 1.24+ enables `X25519MLKEM768` by default in TLS:

```go
// Default config includes PQC - no changes needed
config := &tls.Config{
    MinVersion: tls.VersionTLS13,
}

// Or explicitly configure
config := &tls.Config{
    CurvePreferences: []tls.CurveID{
        tls.X25519MLKEM768,  // Hybrid PQC
        tls.X25519,          // Fallback
    },
}
```

### Migration from BoringCrypto

| Old Setting | New Setting (Go 1.24+) |
|-------------|------------------------|
| `GOEXPERIMENT=boringcrypto` | `GODEBUG=fips140=on` |
| `GOFIPS=1` | `GODEBUG=fips140=on` |
| golang-fips/go fork | Upstream Go 1.24+ |

## Usage Examples

```bash
 kantra analyze \
    --input ./tests/data/testdata \
    --output ~/Desktop/analysis-all \
    --rules ./fips-xcrypto.yaml \
    --rules ./crypto-operational.yaml \
    --rules ./crypto-weak-algorithms.yaml \
    --rules ./crypto-key-strength.yaml \
    --rules ./tls-rules.yaml \
    --rules ./pqc-inventory.yaml \
    --overwrite
```

## Testing

### Run Rule Tests

```bash
cd tests
kantra test --rules ..
```

### Run Analysis on Test Data

```bash
kantra analyze \
  --input ./tests/data/rules-xcrypto \
  --output ./output \
  --rules ./fips-xcrypto.yaml
```

### Test Data Structure

```
tests/
├── data/
│   ├── crypto-key-strength/     # Key size test cases
│   ├── crypto-operational/      # Hardcoded key test cases
│   ├── crypto-weak-algorithms/  # Weak algorithm test cases
│   ├── pqc-inventory/           # PQC inventory test cases
│   ├── pqc-jwt-signatures/      # JWT signature test cases
│   ├── rules-xcrypto/           # x/crypto package test cases
│   ├── rules-simple/            # Basic test Go module structure
│   ├── tls-rules/               # TLS configuration test cases
│   └── testdata/                # General test data
├── crypto-key-strength.test.yaml
├── crypto-operational.test.yaml
├── crypto-weak-algorithms.test.yaml
└── tls-rules.test.yaml
```

## Rule ID Scheme

Rules follow a consistent numbering pattern:

```
fips-go-{category}-{number}
```

| Prefix | Category |
|--------|----------|
| `fips-go-crypto-00xxx` | x/crypto package rules |
| `fips-go-weak-00xxx` | Weak algorithm rules |
| `fips-go-keysize-00xxx` | Key strength rules |
| `fips-go-ops-00xxx` | Operational security rules |
| `fips-go-tls-00xxx` | TLS configuration rules |
| `fips-go-pqc-00xxx` | PQC inventory rules |
| `fips-go-pqc-jwt-00xxx` | JWT signature rules |
| `fips-go-pqc-version-00xxx` | Go version rules |
| `fips-go-pqc-exp-00xxx` | Experimental PQC rules |
| `fips-go-exp-cipher-00xxx` | Experimental cipher suite rules |
| `fips-go-exp-tls-00xxx` | Experimental TLS version rules |

## References

### NIST Publications
- [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final) - Security Requirements for Cryptographic Modules
- [SP 800-131A Rev 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final) - Transitioning Crypto Algorithms
- [SP 800-52 Rev 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final) - TLS Guidelines
- [SP 800-56A Rev 3](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) - Key Establishment
- [SP 800-56C Rev 2](https://csrc.nist.gov/publications/detail/sp/800-56c/rev-2/final) - Key Derivation
- [SP 800-57 Part 1 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) - Key Management
- [SP 800-186](https://csrc.nist.gov/publications/detail/sp/800-186/final) - Discrete Logarithm-Based Cryptography (curve deprecations)
- [FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final) - SHA-3 Standard

### Post-Quantum Cryptography
- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM (Kyber)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA (Dilithium)
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) - SLH-DSA (SPHINCS+)

### Go Documentation
- [Go FIPS 140 Documentation](https://go.dev/doc/security/fips140)
- [Go 1.24 Release Notes](https://go.dev/doc/go1.24)
- [The FIPS 140-3 Go Cryptographic Module](https://go.dev/blog/fips140)
- [Go crypto packages](https://pkg.go.dev/crypto)
- [Go crypto/mlkem](https://pkg.go.dev/crypto/mlkem)
- [Go x/crypto packages](https://pkg.go.dev/golang.org/x/crypto)

### Third-Party PQC Libraries
- [Cloudflare CIRCL](https://github.com/cloudflare/circl)
- [golang-fips/go](https://github.com/golang-fips/go) (legacy)

### Security References
- [RFC 7465](https://datatracker.ietf.org/doc/html/rfc7465) - Prohibiting RC4 Cipher Suites
- [RFC 7568](https://datatracker.ietf.org/doc/html/rfc7568) - Deprecating SSL 3.0
- [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) - TLS 1.3
- [RFC 8996](https://datatracker.ietf.org/doc/html/rfc8996) - Deprecating TLS 1.0 and TLS 1.1
- [Sweet32 Attack](https://sweet32.info/)
- [Lucky13 Attack](https://www.isg.rhul.ac.uk/tls/Lucky13.html)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

### Tools
- [Konveyor](https://www.konveyor.io/)
- [Kantra CLI](https://github.com/konveyor/kantra)

## Contributing

1. Add new rules to the appropriate YAML file
2. Follow the existing rule ID numbering scheme
3. Include clear messages with remediation guidance
4. Add test cases in the `tests/` directory
5. Reference relevant NIST publications
