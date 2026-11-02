/*
Copyright (C) 2026  dyhkwong

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
	"crypto/x509"
	"errors"
	"io"
	"os"
	_ "unsafe"

	"golang.org/x/mobile/asset"
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
	caProviderGo
	caProviderAndroid
	caProviderCustom
)

//go:linkname systemRoots crypto/x509.systemRoots
var systemRoots *x509.CertPool

func UpdateSystemRoots(caProvider int32) (err error) {
	defer func() {
		if err != nil {
			systemRoots = x509.NewCertPool()
		}
	}()
	if caProvider == caProviderGo {
		// can't linkname crypto/x509 initSystemRoots(), do nothing
		return
	}
	x509.SystemCertPool() // crypto/x509 once.Do(initSystemRoots)
	var b []byte
	switch caProvider {
	case caProviderMozilla:
		var file asset.File
		file, err = asset.Open("mozilla_included.pem")
		if err != nil {
			return
		}
		b, err = io.ReadAll(file)
		file.Close()
	case caProviderAndroid:
		if androidCAStore == nil {
			err = errors.New("androidCAStore not initialized")
			return
		}
		b, err = androidCAStore.Certificates()
	case caProviderCustom:
		b, err = os.ReadFile(externalAssetsPath + "root_store.certs")
	default:
		panic("unknown root store provider")
	}
	if err != nil {
		return
	}
	if pool := x509.NewCertPool(); pool.AppendCertsFromPEM(b) {
		systemRoots = pool
	} else {
		err = errors.New("failed to append certificates from pem")
	}
	return
}
