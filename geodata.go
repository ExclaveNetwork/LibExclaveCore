/*
Copyright (C) 2026  lingyicute

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
	"errors"
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/exclavenetwork/exclave-core/v5/app/router/routercommon"
)

// ValidateGeoIPFile checks that the file at path can be decoded as a GeoIPList
// with the same protobuf definition the core uses, and that it contains at
// least one entry. Every entry must have a non-empty country code.
func ValidateGeoIPFile(path string) error {
	data, err := readGeoDataFile(path)
	if err != nil {
		return err
	}
	return validateGeoIPList(data)
}

// ValidateGeoSiteFile checks that the file at path can be decoded as a
// GeoSiteList with the same protobuf definition the core uses, and that it
// contains at least one entry. Every entry must have a non-empty country code.
func ValidateGeoSiteFile(path string) error {
	data, err := readGeoDataFile(path)
	if err != nil {
		return err
	}
	return validateGeoSiteList(data)
}

// ValidateGeoDataFile is for .dat files of unknown kind (user supplied files
// referenced as ext:file.dat:tag). It succeeds if the file is a valid
// GeoIPList or a valid GeoSiteList.
func ValidateGeoDataFile(path string) error {
	data, err := readGeoDataFile(path)
	if err != nil {
		return err
	}
	ipErr := validateGeoIPList(data)
	if ipErr == nil {
		return nil
	}
	if validateGeoSiteList(data) == nil {
		return nil
	}
	return ipErr
}

func readGeoDataFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("empty geodata file")
	}
	return data, nil
}

func validateGeoIPList(data []byte) error {
	var list routercommon.GeoIPList
	if err := proto.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("invalid GeoIPList: %w", err)
	}
	if len(list.Entry) == 0 {
		return errors.New("invalid GeoIPList: no entries")
	}
	for i, entry := range list.Entry {
		if entry.GetCountryCode() == "" {
			return fmt.Errorf("invalid GeoIPList: entry %d has no country code", i)
		}
		// GeoIPList and GeoSiteList share the same outer framing, so also check
		// the inner messages to catch a GeoSiteList installed as a GeoIPList.
		for _, cidr := range entry.Cidr {
			if n := len(cidr.GetIp()); n != 4 && n != 16 {
				return fmt.Errorf("invalid GeoIPList: entry %s has a malformed CIDR", entry.GetCountryCode())
			}
		}
	}
	return nil
}

func validateGeoSiteList(data []byte) error {
	var list routercommon.GeoSiteList
	if err := proto.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("invalid GeoSiteList: %w", err)
	}
	if len(list.Entry) == 0 {
		return errors.New("invalid GeoSiteList: no entries")
	}
	for i, entry := range list.Entry {
		if entry.GetCountryCode() == "" {
			return fmt.Errorf("invalid GeoSiteList: entry %d has no country code", i)
		}
		// See validateGeoIPList: catch a GeoIPList installed as a GeoSiteList.
		for _, domain := range entry.Domain {
			if domain.GetValue() == "" {
				return fmt.Errorf("invalid GeoSiteList: entry %s has an empty domain", entry.GetCountryCode())
			}
		}
	}
	return nil
}
