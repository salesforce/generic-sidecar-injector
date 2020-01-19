/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package util

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/spf13/afero"
)

//TODO Make the Reloader its own thing and have a special case for the Cert one?

// A tool to reload certificates automatically
type CertificateReloader interface {
	Start() error                              // Start the monitoring of the key file
	Stop() chan struct{}                       // Stop the monitoring
	IsRunning() bool                           // Returns true if the reloader is running
	GetCertificate() (*tls.Certificate, error) // Returns the latest certs available and errors if latest cert has expired
}

type CertificatePKIReloader struct {
	refreshInterval time.Duration
	lock            sync.RWMutex
	stopCh          chan struct{}
	stoppedCh       chan struct{}
	started         bool
	lastModTime     time.Time
	certExpiry      time.Time
	fs              afero.Fs
	certFilename    string
	keyFilename     string
	cert            *tls.Certificate
	errHandler      func(error)
}

// FileError indicates there was a problem inspecting or reading the files
// being monitored.
type FileError struct {
	error
}

// TLSError indicates there was a problem converting the contents of the
// monitored files into x509 certificate/key pair.
type TLSError struct {
	error
}

// Creates a CertificateReloader based on the files and afero FS.
func NewCertificatePKIReloaderFull(fs afero.Fs, certFilename, keyFilename string, refreshInterval time.Duration) *CertificatePKIReloader {
	return newCertificatePKIReloaderFull(
		fs,
		certFilename,
		keyFilename,
		refreshInterval,
		nil,
	)
}

// Creates a CertificateReloader based on the files and afero FS.
// Calls the given error handler when there are problems reading the given
// files. The error passed to the handler will be a FileError, TLSError, or
// error.
// If errHandler is nil, the default behavior is to do nothing on error.
func NewCertificatePKIReloaderFullWithErrHandler(fs afero.Fs, certFilename, keyFilename string, refreshInterval time.Duration, errHandler func(error)) *CertificatePKIReloader {
	return newCertificatePKIReloaderFull(
		fs,
		certFilename,
		keyFilename,
		refreshInterval,
		errHandler,
	)
}

// A simplified version of NewCertificatePKIReloaderFull where the fs is the OS fs by default
func NewCertificatePKIReloader(certFilename, keyFilename string, refreshInterval time.Duration) *CertificatePKIReloader {
	return NewCertificatePKIReloaderFull(
		afero.NewOsFs(),
		certFilename,
		keyFilename,
		refreshInterval)
}

// A simplified version of NewCertificatePKIReloaderFullWithErrHandler where the
// fs is the OS fs by default.
// Calls the given error handler when there are problems reading the given
// files. The error passed to the handler will be a FileError, TLSError, or
// error.
// If errHandler is nil, the default behavior is to do nothing on error.
func NewCertificatePKIReloaderWithErrHandler(certFilename, keyFilename string, refreshInterval time.Duration, errHandler func(error)) *CertificatePKIReloader {
	return newCertificatePKIReloaderFull(
		afero.NewOsFs(),
		certFilename,
		keyFilename,
		refreshInterval,
		errHandler,
	)
}

func newCertificatePKIReloaderFull(fs afero.Fs, certFilename, keyFilename string, refreshInterval time.Duration, errHandler func(error)) *CertificatePKIReloader {
	if errHandler == nil {
		errHandler = func(_ error) { /* Do nothing */ }
	}

	return &CertificatePKIReloader{
		fs:              fs,
		certFilename:    certFilename,
		keyFilename:     keyFilename,
		refreshInterval: refreshInterval,
		started:         false,
		errHandler:      errHandler,
	}
}

func (r *CertificatePKIReloader) Start() error {
	if r == nil {
		panic("Calling Start on uninit CertificatePKIReloader")
	}
	if !r.started {
		r.runRefresh()
		if _, err := r.GetCertificate(); err != nil {
			return err
		}
		r.stopCh = make(chan struct{})
		r.stoppedCh = make(chan struct{})
		r.started = true
		go r.runRefreshLoop()
	}

	return nil
}

func (r *CertificatePKIReloader) Stop() chan struct{} {
	if r == nil {
		panic("Calling Start on uninit CertificatePKIReloader")
	}
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.started {
		stoppedCh := make(chan struct{})
		close(stoppedCh)
		return stoppedCh
	}

	close(r.stopCh)
	r.started = false
	return r.stoppedCh
}

func (r *CertificatePKIReloader) IsRunning() bool {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.started
}

func (r *CertificatePKIReloader) GetCertificate() (*tls.Certificate, error) {
	if r == nil {
		panic("Calling Start on uninit CertificatePKIReloader")
	}
	r.lock.RLock()
	defer r.lock.RUnlock()
	// return error if certificate in cache has expired
	if r.certExpiry.Before(time.Now()) {
		return nil, fmt.Errorf("certificate expired at %v", r.certExpiry)
	}
	return r.cert, nil
}

func readCert(fs afero.Fs, certFilename, keyFilename string) (*tls.Certificate, error) {
	certPEMBlock, err := afero.ReadFile(fs, certFilename)
	if err != nil {
		return &tls.Certificate{}, FileError{error: err}
	}

	keyPEMBlock, err := afero.ReadFile(fs, keyFilename)
	if err != nil {
		return &tls.Certificate{}, FileError{error: err}
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return &tls.Certificate{}, TLSError{error: err}
	}
	return &cert, nil
}

func readModTime(fs afero.Fs, filename string) (time.Time, error) {
	f, err := fs.Stat(filename)
	if err != nil {
		return time.Time{}, nil
	}

	return f.ModTime(), nil
}

func (r *CertificatePKIReloader) runRefresh() {
	modTime, err := readModTime(r.fs, r.keyFilename)
	if err != nil {
		r.errHandler(err)
		return
	}

	if r.lastModTime.Before(modTime) {
		cert, err := readCert(r.fs, r.certFilename, r.keyFilename)
		if err != nil {
			r.errHandler(err)
			return
		}
		clientCert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			r.errHandler(err)
			return
		}
		r.lock.Lock()
		// cert, lastModTime, certExpiry are not updated in case of errors reading the cert
		r.lastModTime = modTime
		r.cert = cert
		r.certExpiry = clientCert.NotAfter
		r.lock.Unlock()
	}
}

func (r *CertificatePKIReloader) runRefreshLoop() {
	defer close(r.stoppedCh)

	ticker := time.NewTicker(r.refreshInterval)
	for {
		select {
		case <-ticker.C:
			r.runRefresh()
		case <-r.stopCh:
			return
		}
	}
}
