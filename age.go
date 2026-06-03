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
	"bytes"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func AgeArmerDecrypt(data []byte, privateKey string) ([]byte, error) {
	identities, err := age.ParseIdentities(strings.NewReader(privateKey))
	if err != nil {
		return nil, err
	}
	reader, err := age.Decrypt(armor.NewReader(bytes.NewReader(data)), identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}
