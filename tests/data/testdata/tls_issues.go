package main

import (
	"crypto/tls"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	config := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	_ = config
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


