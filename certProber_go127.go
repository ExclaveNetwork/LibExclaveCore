//go:build go1.27

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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"encoding/hex"
	"strconv"
	"strings"
)

func publicKeyToString(certInfo *strings.Builder, publicKey any) {
	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		certInfo.WriteString("  Public Key Size: " + strconv.Itoa(publicKey.N.BitLen()) + "\n\n")
		certInfo.WriteString("  Modulus: " + hex.EncodeToString(publicKey.N.Bytes()) + "\n\n")
		certInfo.WriteString("  Public Exponent: " + strconv.Itoa(publicKey.E) + "\n\n")
	case *ecdsa.PublicKey:
		certInfo.WriteString("  Public Key Size: " + strconv.Itoa(publicKey.Params().BitSize) + "\n\n")
		ecdhPublicKey, err := publicKey.ECDH()
		if err != nil {
			panic(err)
		}
		certInfo.WriteString("  Public Key: " + hex.EncodeToString(ecdhPublicKey.Bytes()) + "\n\n")
	case ed25519.PublicKey:
		certInfo.WriteString("  Public Key: " + hex.EncodeToString(publicKey) + "\n\n")
	case *mldsa.PublicKey:
		certInfo.WriteString("  Public Key Size: " + strconv.Itoa(publicKey.Parameters().PublicKeySize()) + "\n\n")
		certInfo.WriteString("  Public Key: " + hex.EncodeToString(publicKey.Bytes()) + "\n\n")
	}
}
