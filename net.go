/*
Copyright (C) 2025  dyhkwong

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
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func IsIP(input string) bool {
	_, err := netip.ParseAddr(input)
	return err == nil
}

func IsIPv4(input string) bool {
	ip, err := netip.ParseAddr(input)
	if err != nil {
		return false
	}
	return ip.Is4()
}

func IsIPv6(input string) bool {
	ip, err := netip.ParseAddr(input)
	if err != nil {
		return false
	}
	return ip.Is6()
}

func IsLoopbackIP(input string) bool {
	ip, err := netip.ParseAddr(input)
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}

type HostPort struct {
	Host string
	Port int32
}

func SplitHostPort(str string) (*HostPort, error) {
	host, portStr, err := net.SplitHostPort(str)
	if err != nil {
		return nil, err
	}
	for _, b := range portStr {
		if b < '0' || b > '9' {
			return nil, errors.New("port not numeric")
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if strings.Contains(host, ":") && !IsIPv6(host) {
		return nil, errors.New("non-IPv6 hostname contains colons")
	}
	return &HostPort{
		Host: host,
		Port: int32(port),
	}, nil
}
