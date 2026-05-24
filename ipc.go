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
	"encoding/binary"
	"io"
	"net"
	"os"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
)

var (
	_ net.Conn       = (*ipcConn)(nil)
	_ net.PacketConn = (*ipcPacketConn)(nil)
	_ net.Addr       = (*udpAddr)(nil)
)

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, v2rayNet.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x04, v2rayNet.AddressFamilyIPv6),
	protocol.AddressFamilyByte(0x03, v2rayNet.AddressFamilyDomain),
)

type ipcConn struct {
	net.Conn
	headerWritten bool
	dest          v2rayNet.Destination
}

func newIPCConn(conn net.Conn, dest v2rayNet.Destination) *ipcConn {
	return &ipcConn{
		Conn: conn,
		dest: dest,
	}
}

func (c *ipcConn) writeHeader(command byte) (int, error) {
	buffer := buf.StackNew()
	defer buffer.Release()
	buffer.WriteByte(command)
	addrParser.WriteAddressPort(&buffer, c.dest.Address, c.dest.Port)
	return c.Conn.Write(buffer.Bytes())
}

func (c *ipcConn) Write(b []byte) (int, error) {
	if !c.headerWritten {
		_, err := c.writeHeader(0x01)
		if err != nil {
			return 0, err
		}
		c.headerWritten = true
	}
	return c.Conn.Write(b)
}

func newIPCPacketConn(conn net.Conn, dest v2rayNet.Destination) *ipcPacketConn {
	return &ipcPacketConn{
		ipcConn: newIPCConn(conn, dest),
	}
}

type ipcPacketConn struct {
	*ipcConn
	alwaysNetUDPAddr bool // always use net.UDPAddr
}

func (c *ipcPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	addr, port, err := addrParser.ReadAddressPort(nil, c)
	if err != nil {
		return 0, nil, err
	}
	var b [2]byte
	_, err = c.Read(b[:])
	if err != nil {
		return 0, nil, err
	}
	length := min(int(binary.BigEndian.Uint16(b[:])), len(p))
	_, err = io.ReadFull(c, p[:length])
	if err != nil {
		return 0, nil, err
	}
	if addr.Family().IsIP() {
		return length, &net.UDPAddr{
			IP:   addr.IP(),
			Port: int(port),
		}, nil
	}
	if addr.Family().IsDomain() && c.alwaysNetUDPAddr {
		return 0, nil, os.ErrInvalid
	}
	return length, &udpAddr{
		address: net.JoinHostPort(addr.Domain(), port.String()),
	}, nil
}

func (c *ipcPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dest, err := v2rayNet.ParseDestination(addr.String())
	if err != nil {
		return 0, err
	}
	if !c.headerWritten {
		_, err = c.writeHeader(0x03)
		if err != nil {
			return 0, err
		}
		c.headerWritten = true
	}
	err = addrParser.WriteAddressPort(c.Conn, dest.Address, dest.Port)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write([]byte{byte(len(p) >> 8), byte(len(p))})
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

type udpAddr struct {
	address string
}

func (a *udpAddr) Network() string {
	return "udp"
}

func (a *udpAddr) String() string {
	return a.address
}
