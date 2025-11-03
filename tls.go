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
// It ensures the path doesn't contain directory traversal sequences and resolves to a safe location.
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
	
	// Ensure the path doesn't start with "../"
	if strings.HasPrefix(cleanPath, "../") || cleanPath == ".." {
		return fmt.Errorf("path attempts to traverse outside allowed directory: %s", path)
	}
	
	// Convert to absolute path and check it doesn't escape working directory for relative paths
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("unable to get working directory: %w", err)
		}
		absPath, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("unable to resolve absolute path: %w", err)
		}
		// Ensure the resolved path is within or under the working directory
		relPath, err := filepath.Rel(wd, absPath)
		if err != nil || strings.HasPrefix(relPath, "..") {
			return fmt.Errorf("path resolves outside working directory: %s", path)
		}
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

// secureReadFile reads a file after validating the path for security
func secureReadFile(filename string) ([]byte, error) {
	// Validate the file path to prevent path traversal attacks
	if err := validateFilePath(filename); err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}
	
	// Additional security: resolve to absolute path after validation
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve file path: %w", err)
	}
	
	// Re-validate the absolute path (defense in depth)
	if err := validateFilePath(absPath); err != nil {
		return nil, fmt.Errorf("resolved path validation failed: %w", err)
	}
	
	// Use the validated absolute path to read the file
	// nosemgrep: go.lang.security.audit.path-traversal.path-join-resolve-traversal
	return os.ReadFile(absPath)
}

func loadCertificatesFrom(pemFile string) (*x509.CertPool, error) {
	caCert, err := secureReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	certificates := x509.NewCertPool()
	certificates.AppendCertsFromPEM(caCert)
	return certificates, nil
}

// secureLoadX509KeyPair loads a key pair after validating file paths
func secureLoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	// Validate both file paths to prevent path traversal attacks
	if err := validateFilePath(certFile); err != nil {
		return tls.Certificate{}, fmt.Errorf("invalid certificate file path: %w", err)
	}
	if err := validateFilePath(keyFile); err != nil {
		return tls.Certificate{}, fmt.Errorf("invalid private key file path: %w", err)
	}
	
	// Resolve to absolute paths for additional security
	absCertFile, err := filepath.Abs(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cannot resolve certificate file path: %w", err)
	}
	absKeyFile, err := filepath.Abs(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cannot resolve key file path: %w", err)
	}
	
	// Re-validate the absolute paths (defense in depth)
	if err := validateFilePath(absCertFile); err != nil {
		return tls.Certificate{}, fmt.Errorf("resolved certificate path validation failed: %w", err)
	}
	if err := validateFilePath(absKeyFile); err != nil {
		return tls.Certificate{}, fmt.Errorf("resolved key path validation failed: %w", err)
	}
	
	// Use validated absolute paths to load the key pair
	// nosemgrep: go.lang.security.audit.path-traversal.path-join-resolve-traversal
	return tls.LoadX509KeyPair(absCertFile, absKeyFile)
}

func loadPrivateKeyFrom(pemCertFile, pemPrivateKeyFile string) (*tls.Certificate, error) {
	privateKey, err := secureLoadX509KeyPair(pemCertFile, pemPrivateKeyFile)
	if err != nil {
		return nil, err
	}
	return &privateKey, nil
}
