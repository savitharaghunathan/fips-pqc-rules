package main

import (
	"crypto/tls"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/client-go/rest"
)

// Test: fips-go-tls-00100 - InsecureSkipVerify
func insecureSkipVerify() {
	// Direct assignment
	config1 := &tls.Config{
		InsecureSkipVerify: true,
	}
	_ = config1

	// Field assignment
	config2 := &tls.Config{}
	config2.InsecureSkipVerify = true
	_ = config2
}

// Test: fips-go-tls-00101 - MaxVersion blocks TLS 1.3
func maxVersionBlocking() {
	// Blocks TLS 1.3 and PQC
	config1 := &tls.Config{
		MaxVersion: tls.VersionTLS12,
	}
	_ = config1

	config2 := &tls.Config{}
	config2.MaxVersion = tls.VersionTLS11
	_ = config2
}

// Test: fips-go-tls-00102 - Hardcoded CipherSuites
func hardcodedCipherSuites() {
	// Struct literal initialization
	config := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	_ = config

	// Assignment form
	config2 := &tls.Config{}
	config2.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	_ = config2

	// Append form
	config3 := &tls.Config{}
	config3.CipherSuites = append(config3.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	_ = config3
}

// Test: fips-go-tls-00103 - Certificate validation override
func certValidationOverride() {
	config1 := &tls.Config{}
	config1.VerifyPeerCertificate = nil
	config1.RootCAs = nil
	config1.ClientCAs = nil

	// Empty verify function
	config2 := &tls.Config{
		VerifyConnection: func(cs tls.ConnectionState) error {
			return nil
		},
	}
	_ = config2
}

// Test: fips-go-tls-00104 - gRPC insecure credentials
func grpcInsecure() {
	// Deprecated method
	conn1, _ := grpc.Dial("server:443", grpc.WithInsecure())
	_ = conn1

	// New insecure credentials
	conn2, _ := grpc.Dial("server:443",
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	_ = conn2

	// Direct insecure credentials
	creds := insecure.NewCredentials()
	_ = creds
}

// Test: fips-go-tls-00109 - gRPC custom TLS credential override
func grpcCustomTLS() {
	// Custom TLS config passed to gRPC credentials
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	creds := credentials.NewTLS(tlsConfig)
	conn, _ := grpc.Dial("server:443",
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	_ = conn
	_ = creds
}

// Test: fips-go-tls-00110 - Kubernetes client custom TLS override
func k8sClientCustomTLS() {
	// Custom TLS in rest.Config
	config := &rest.Config{
		TLSClientConfig: rest.TLSClientConfig{
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		},
	}
	_ = config

	// Assignment form
	config2 := &rest.Config{}
	config2.TLSClientConfig = rest.TLSClientConfig{
		CAFile: "/path/to/ca.pem",
	}
	_ = config2

	// CertData inline
	config3 := &rest.Config{
		TLSClientConfig: rest.TLSClientConfig{
			CertData: []byte("cert-data"),
		},
	}
	_ = config3
}

// Test: fips-go-tls-00106 - Plain HTTP (potential service mesh bypass)
func plainHTTP() {
	// Plain HTTP calls
	resp, _ := http.Get("http://api.example.com/data")
	_ = resp

	resp2, _ := http.Post("http://api.example.com/submit", "application/json", nil)
	_ = resp2
}

// Test: fips-go-tls-00107 - Database TLS disabled
func databaseTLSDisabled() {
	// PostgreSQL
	connStr1 := "postgres://user:pass@host:5432/db?sslmode=disable"
	_ = connStr1

	// MySQL
	connStr2 := "user:pass@tcp(host:3306)/db?tls=false"
	_ = connStr2

	// Generic SSL disabled
	connStr3 := "host=db ssl=false"
	_ = connStr3
}

// Test: fips-go-tls-00108 - Empty ServerName
func emptyServerName() {
	config := &tls.Config{}
	config.ServerName = ""
	_ = config
}

// Test: fips-go-tls-00205 - Hardcoded TLS 1.3
func hardcodedTLS13() {
	// Hardcoded MinVersion TLS 1.3
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	_ = config

	// Hardcoded MaxVersion TLS 1.3
	config2 := &tls.Config{}
	config2.MaxVersion = tls.VersionTLS13
	_ = config2
}

// Test: fips-go-tls-00206 - CurvePreferences blocks PQC
func curvePreferencesBlockPQC() {
	// Explicit CurvePreferences without PQC curves
	config := &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
	_ = config

	// Assignment form
	config2 := &tls.Config{}
	config2.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.CurveP384}
	_ = config2
}

// Test: fips-go-tls-00207 - X25519 without ML-KEM
func x25519WithoutMLKEM() {
	config := &tls.Config{
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
	_ = config
}

// Test: fips-go-tls-00200 - Manual tls.Config creation
func manualTLSConfig() {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	_ = config

	config2 := tls.Config{}
	_ = config2
}

// Test: fips-go-tls-00201 - MinVersion hardcoded
func minVersionHardcoded() {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	_ = config

	config2 := &tls.Config{}
	config2.MinVersion = tls.VersionTLS10
	_ = config2
}

// Test: fips-go-tls-00202 - HTTP client custom TLS
func httpClientCustomTLS() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	_ = transport

	transport2 := http.Transport{}
	transport2.TLSClientConfig = &tls.Config{}
	_ = transport2
}

// Test: fips-go-tls-00203 - HTTP server custom TLS
func httpServerCustomTLS() {
	server := &http.Server{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	_ = server
}


