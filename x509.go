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
	"encoding/pem"
	"errors"
	"strings"
)

func PemToDer(input string) ([]byte, error) {
	var der []byte
	data := []byte(input)
	ok := false
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			continue
		}
		der = append(der, block.Bytes...)
		ok = true
	}
	if !ok {
		return nil, errors.New("invalid certificate")
	}
	return der, nil
}

func DerToPem(input []byte) (string, error) {
	certs, err := x509.ParseCertificates(input)
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	for _, cert := range certs {
		if err := pem.Encode(&builder, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return "", err
		}
	}
	return builder.String(), nil
}
