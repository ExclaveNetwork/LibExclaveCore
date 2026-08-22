/*
Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package libexclavecore

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	_ "unsafe"

	"golang.org/x/mobile/asset"
	"golang.org/x/sys/unix"
)

type AndroidCAStore interface {
	Certificates() ([]byte, error)
}

var androidCAStore AndroidCAStore

func RegisterAndroidCAStore(store AndroidCAStore) {
	androidCAStore = store
}

const (
	caProviderMozilla = iota
	caProviderSystem
	caProviderSystemAndUser // for https://github.com/golang/go/issues/71258
	caProviderCustom
)

const (
	mozillaIncludedPem = "mozilla_included.pem"
	androidIncludedPem = "android_included.pem"
	customPem          = "root_store.certs"
)

//go:linkname systemRoots crypto/x509.systemRoots
var systemRoots *x509.CertPool

func UpdateSystemRoots(caProvider int32) (err error) {
	switch caProvider {
	case caProviderSystem:
	case caProviderMozilla:
		err = setupMozillaCAProvider()
	case caProviderCustom:
		err = setupCustomCAProvider()
	case caProviderSystemAndUser:
		err = setupSystemAndUserCAProvider()
	default:
		panic("unknown root store provider")
	}
	if err != nil {
		x509.SystemCertPool() // crypto/x509 once.Do(initSystemRoots)
		systemRoots = x509.NewCertPool()
		return err
	}
	return nil
}

func extractOrReadMozillaCAPem() ([]byte, error) {
	pemInternal, err := asset.Open(mozillaIncludedPem)
	if err != nil {
		pemInternal.Close()
		return nil, err
	}
	pemBytes, err := io.ReadAll(pemInternal)
	if err != nil {
		pemInternal.Close()
		return nil, err
	}
	pemInternal.Close()
	pemFile, err := os.OpenFile(internalAssetsPath+mozillaIncludedPem, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	defer pemFile.Close()
	if err := unix.Flock(int(pemFile.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(int(pemFile.Fd()), unix.LOCK_UN)
	if b, err := io.ReadAll(pemFile); err == nil && bytes.Equal(b, pemBytes) {
		return pemBytes, nil
	}
	if err := pemFile.Truncate(0); err != nil {
		return nil, err
	}
	if _, err := pemFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := pemFile.Write(pemBytes); err != nil {
		return nil, err
	}
	return pemBytes, nil
}

func setupMozillaCAProvider() error {
	pemBytes, err := extractOrReadMozillaCAPem()
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return errors.New("failed to append certificates from pem")
	}
	x509.SystemCertPool()
	systemRoots = roots
	return nil
}

func setupCustomCAProvider() error {
	pemBytes, err := os.ReadFile(externalAssetsPath + customPem)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return errors.New("failed to append certificates from pem")
	}
	x509.SystemCertPool()
	systemRoots = roots
	return nil
}

func setupSystemAndUserCAProvider() error {
	if androidCAStore == nil {
		return errors.New("androidCAStore not initialized")
	}
	der, err := androidCAStore.Certificates()
	if err != nil {
		return err
	}
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return err
	}
	pemFile, err := os.Create(internalAssetsPath + androidIncludedPem) // for plugins
	if err != nil {
		return err
	}
	defer pemFile.Close()
	if err := unix.Flock(int(pemFile.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(int(pemFile.Fd()), unix.LOCK_UN)
	roots := x509.NewCertPool()
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := pem.Encode(pemFile, block); err != nil {
			return err
		}
		roots.AddCert(cert)
	}
	x509.SystemCertPool()
	systemRoots = roots
	return nil
}
