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
	"net"
	"net/url"
	"strconv"
	"strings"
	_ "unsafe"

	"github.com/exclavenetwork/exclave-core/v5/common/errors"
)

type URL interface {
	GetScheme() string
	SetScheme(scheme string)
	GetOpaque() string
	SetOpaque(opaque string)
	GetUserInfo() string
	SetUsernamePassword(username, password string)
	HasUsername() bool
	GetUsername() string
	SetUsername(username string)
	HasPassword() bool
	GetPassword() string
	SetPassword(password string)
	GetHost() string
	SetHost(host string)
	HasPort() bool
	GetPort() int32
	SetHostPort(host string, port int32)
	SetRawHost(host string)
	GetRawHost() string
	GetPath() string
	SetPath(path string)
	GetRawPath() string
	SetRawPath(rawPath string) error
	GetRawQuery() string
	SetRawQuery(rawPath string)
	CountQueryParameters() int
	HasQueryParameter(key string) bool
	CountQueryParameter(key string) int
	GetQueryParameter(key string) string
	GetQueryParameterAt(key string, i int) string
	AddQueryParameter(key, value string)
	SetQueryParameter(key, value string)
	DeleteQueryParameter(key string)
	QueryParameters() *QueryParameters
	GetFragment() string
	SetFragment(fragment string)
	GetRawFragment() string
	SetRawFragment(rawFragment string) error
	GetString() string
}

var _ URL = (*netURL)(nil)

type netURL struct {
	*url.URL
}

func NewURL(scheme string) URL {
	return &netURL{
		URL: &url.URL{
			Scheme: scheme,
		},
	}
}

//go:linkname setFragment net/url.(*URL).setFragment
func setFragment(u *url.URL, fragment string) error

//go:linkname setPath net/url.(*URL).setPath
func setPath(u *url.URL, fragment string) error

func ParseURL(rawURL string) (URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if strings.Contains(u.Hostname(), ":") && !IsIPv6(u.Hostname()) {
		// https://github.com/golang/go/issues/75223
		// https://github.com/golang/go/issues/75859
		// https://github.com/golang/go/issues/78077
		// https://github.com/golang/go/issues/78945
		return nil, errors.New("non-IPv6 hostname contains colons")
	}
	return &netURL{URL: u}, nil
}

func (u *netURL) GetScheme() string {
	return u.Scheme
}

func (u *netURL) SetScheme(scheme string) {
	u.Scheme = scheme
}

func (u *netURL) GetOpaque() string {
	return u.Opaque
}

func (u *netURL) SetOpaque(opaque string) {
	u.Opaque = opaque
}

func (u *netURL) GetUserInfo() string {
	if u.User != nil {
		return u.User.String()
	}
	return ""
}

func (u *netURL) SetUsernamePassword(username, password string) {
	u.User = url.UserPassword(username, password)
}

func (u *netURL) HasUsername() bool {
	if u.User != nil {
		return true
	}
	return false
}

func (u *netURL) GetUsername() string {
	if u.User != nil {
		return u.User.Username()
	}
	return ""
}

func (u *netURL) SetUsername(username string) {
	if u.User != nil {
		if password, ok := u.User.Password(); !ok {
			u.User = url.User(username)
		} else {
			u.User = url.UserPassword(username, password)
		}
	} else {
		u.User = url.User(username)
	}
}

func (u *netURL) HasPassword() bool {
	if u.User == nil {
		return false
	}
	_, passwordSet := u.User.Password()
	return passwordSet
}

func (u *netURL) GetPassword() string {
	if u.User != nil {
		if password, ok := u.User.Password(); ok {
			return password
		}
	}
	return ""
}

func (u *netURL) SetPassword(password string) {
	if u.User == nil {
		u.User = url.UserPassword("", password)
	}
	u.User = url.UserPassword(u.User.Username(), password)
}

func (u *netURL) GetHost() string {
	return u.Hostname()
}

func (u *netURL) SetHost(host string) {
	// See net.JoinHostPort
	if strings.IndexByte(host, ':') >= 0 {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
}

func (u *netURL) HasPort() bool {
	_, portStr, err := net.SplitHostPort(u.Host)
	return err == nil && len(portStr) > 0
}

func (u *netURL) GetPort() int32 {
	portStr := u.Port()
	if portStr == "" {
		return 0
	}
	port, _ := strconv.Atoi(portStr)
	return int32(port)
}

func (u *netURL) SetHostPort(host string, port int32) {
	u.Host = net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func (u *netURL) GetRawHost() string {
	return u.Host
}

func (u *netURL) SetRawHost(host string) {
	u.Host = host
}

func (u *netURL) GetPath() string {
	return u.Path
}

func (u *netURL) SetPath(path string) {
	u.Path = path
	u.RawPath = ""
}

func (u *netURL) GetRawPath() string {
	if len(u.RawPath) > 0 {
		return u.RawPath
	}
	return u.Path
}

func (u *netURL) SetRawPath(rawPath string) error {
	return setPath(u.URL, rawPath)
}

func (u *netURL) GetRawQuery() string {
	return u.RawQuery
}

func (u *netURL) SetRawQuery(rawQuery string) {
	u.RawQuery = rawQuery
}

func (u *netURL) CountQueryParameters() int {
	return len(u.Query())
}

func (u *netURL) HasQueryParameter(key string) bool {
	return u.Query().Has(key)
}

func (u *netURL) GetQueryParameter(key string) string {
	return u.Query().Get(key)
}

func (u *netURL) CountQueryParameter(key string) int {
	value, ok := u.Query()[key]
	if !ok {
		return 0
	}
	return len(value)
}

func (u *netURL) GetQueryParameterAt(key string, i int) string {
	value, ok := u.Query()[key]
	if !ok {
		return ""
	}
	if i < 0 || i >= len(value) {
		return ""
	}
	return value[i]
}

func (u *netURL) AddQueryParameter(key, value string) {
	queries := u.Query()
	queries.Add(key, value)
	u.RawQuery = queries.Encode()
}

func (u *netURL) SetQueryParameter(key, value string) {
	queries := u.Query()
	queries.Set(key, value)
	u.RawQuery = queries.Encode()
}

func (u *netURL) DeleteQueryParameter(key string) {
	queries := u.Query()
	queries.Del(key)
	u.RawQuery = queries.Encode()
}

type QueryParameters struct {
	size   int
	keys   []string
	values []string
}

func (q *QueryParameters) Size() int {
	return q.size
}

func (q *QueryParameters) GetKeyAt(i int) string {
	return q.keys[i]
}

func (q *QueryParameters) GetValueAt(i int) string {
	return q.values[i]
}

func (u *netURL) QueryParameters() *QueryParameters {
	queryParameters := new(QueryParameters)
	for key, values := range u.Query() {
		for _, value := range values {
			queryParameters.size++
			queryParameters.keys = append(queryParameters.keys, key)
			queryParameters.values = append(queryParameters.values, value)
		}
	}
	return queryParameters
}

func (u *netURL) SetFragment(fragment string) {
	u.Fragment = fragment
	u.RawFragment = ""
}

func (u *netURL) GetFragment() string {
	return u.Fragment
}

func (u *netURL) SetRawFragment(rawFragment string) error {
	return setFragment(u.URL, rawFragment)
}

func (u *netURL) GetRawFragment() string {
	if len(u.RawFragment) > 0 {
		return u.RawFragment
	}
	return u.Fragment
}

func (u *netURL) GetString() string {
	return u.String()
}
