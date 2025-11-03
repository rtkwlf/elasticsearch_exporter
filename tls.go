// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// validateFilePath validates that a file path is safe to use and prevents path traversal attacks.
// It ensures the path doesn't contain directory traversal sequences and is within allowed bounds.
func validateFilePath(path string) error {
	if path == "" {
		return nil // Empty paths are allowed (will be skipped)
	}
	
	// Clean the path to resolve any ".." or "." elements
	cleanPath := filepath.Clean(path)
	
	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path contains directory traversal sequences: %s", path)
	}
	
	// Ensure the path is absolute or relative but doesn't start with ".."
	if strings.HasPrefix(cleanPath, "../") || cleanPath == ".." {
		return fmt.Errorf("path attempts to traverse outside allowed directory: %s", path)
	}
	
	return nil
}

func createTLSConfig(pemFile, pemCertFile, pemPrivateKeyFile string, insecureSkipVerify bool) *tls.Config {
	tlsConfig := tls.Config{}
	if insecureSkipVerify {
		// pem settings are irrelevant if we're skipping verification anyway
		tlsConfig.InsecureSkipVerify = true
	}
	if len(pemFile) > 0 {
		rootCerts, err := loadCertificatesFrom(pemFile)
		if err != nil {
			log.Fatalf("Couldn't load root certificate from %s. Got %s.", pemFile, err)
			return nil
		}
		tlsConfig.RootCAs = rootCerts
	}
	if len(pemCertFile) > 0 && len(pemPrivateKeyFile) > 0 {
		// Load files once to catch configuration error early.
		_, err := loadPrivateKeyFrom(pemCertFile, pemPrivateKeyFile)
		if err != nil {
			log.Fatalf("Couldn't setup client authentication. Got %s.", err)
			return nil
		}
		// Define a function to load certificate and key lazily at TLS handshake to
		// ensure that the latest files are used in case they have been rotated.
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return loadPrivateKeyFrom(pemCertFile, pemPrivateKeyFile)
		}
	}
	return &tlsConfig
}

func loadCertificatesFrom(pemFile string) (*x509.CertPool, error) {
	// Validate the file path to prevent path traversal attacks
	if err := validateFilePath(pemFile); err != nil {
		return nil, fmt.Errorf("invalid certificate file path: %w", err)
	}
	
	caCert, err := os.ReadFile(pemFile)
	if err != nil {
		return nil, err
	}
	certificates := x509.NewCertPool()
	certificates.AppendCertsFromPEM(caCert)
	return certificates, nil
}

func loadPrivateKeyFrom(pemCertFile, pemPrivateKeyFile string) (*tls.Certificate, error) {
	// Validate both file paths to prevent path traversal attacks
	if err := validateFilePath(pemCertFile); err != nil {
		return nil, fmt.Errorf("invalid certificate file path: %w", err)
	}
	if err := validateFilePath(pemPrivateKeyFile); err != nil {
		return nil, fmt.Errorf("invalid private key file path: %w", err)
	}
	
	privateKey, err := tls.LoadX509KeyPair(pemCertFile, pemPrivateKeyFile)
	if err != nil {
		return nil, err
	}
	return &privateKey, nil
}
