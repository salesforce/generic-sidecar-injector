/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestGetAnnotation(t *testing.T) {
	assert.Equal(t, "annotation.io/key", GetAnnotation("annotation.io", "key"))
}

func TestMergeVolumes(t *testing.T) {
	target := []corev1.Volume{
		{
			Name: "one",
		},
		{
			Name: "two",
		},
	}
	added := []corev1.Volume{
		{
			Name: "two",
		},
		{
			Name: "three",
		},
	}
	merged := MergeVolumes(target, added)

	assert.Len(t, merged, 3)
	assert.Equal(t, "one", merged[0].Name)
	assert.Equal(t, "two", merged[1].Name)
	assert.Equal(t, "three", merged[2].Name)
}

func TestMergeVolumeMounts(t *testing.T) {
	target := []corev1.VolumeMount{
		{
			Name: "one",
		},
		{
			Name: "two",
		},
	}
	added := []corev1.VolumeMount{
		{
			Name: "one",
		},
	}
	merged := MergeVolumeMounts(target, added)

	assert.Len(t, merged, 2)
	assert.Equal(t, "one", merged[0].Name)
	assert.Equal(t, "two", merged[1].Name)
}

func TestMergeVolumeMountsNoDuplicates(t *testing.T) {
	target := []corev1.VolumeMount{
		{
			Name: "one",
		},
		{
			Name: "two",
		},
	}
	added := []corev1.VolumeMount{
		{
			Name: "three",
		},
		{
			Name: "four",
		},
	}
	merged := MergeVolumeMounts(target, added)

	assert.Len(t, merged, 4)
	assert.Equal(t, "one", merged[0].Name)
	assert.Equal(t, "two", merged[1].Name)
	assert.Equal(t, "three", merged[2].Name)
	assert.Equal(t, "four", merged[3].Name)
}

// TempCerts for temporary certificates
type TempCerts struct {
	certsDirectory string
	certFileName   string
	keyFileName    string
}

// GenerateTestCertificates generates test certificates
func GenerateTestCertificates() (*TempCerts, error) {
	// Source - https://golang.org/src/crypto/tls/generate_cert.go

	var err error
	tempDir, err := ioutil.TempDir("", "test-certs")
	if err != nil {
		return nil, fmt.Errorf("failed to create a temp directory: %s", err)
	}

	certFileName := filepath.Join(tempDir, "cert.pem")
	keyFileName := filepath.Join(tempDir, "key.pem")

	var privateKey *rsa.PrivateKey
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Salesforce.com"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}

	publicKey := &privateKey.PublicKey
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate: %s", err)
	}

	err = writePemBlockToFile(certFileName, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, err
	}

	err = writePemBlockToFile(keyFileName, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		return nil, err
	}

	return &TempCerts{
		certsDirectory: tempDir,
		certFileName:   certFileName,
		keyFileName:    keyFileName,
	}, nil
}

func writePemBlockToFile(fileName string, pemBlock *pem.Block) error {
	certOut, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to create %s: %s", fileName, err)
	}

	if err := pem.Encode(certOut, pemBlock); err != nil {
		return fmt.Errorf("failed to write block to file: %s", err)
	}

	if err := certOut.Close(); err != nil {
		return fmt.Errorf("unable to close %s: %s", fileName, err)
	}

	return nil
}
