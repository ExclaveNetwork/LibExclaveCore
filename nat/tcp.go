/*
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

package nat

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type tcpForwarder struct {
	tun       *SystemTun
	addr4     netip.Addr
	addr4Next netip.Addr
	addr6     netip.Addr
	addr6Next netip.Addr
	port      uint16
	listener  net.Listener
	tcpNAT    *tcpNAT
	cancel    context.CancelFunc
}

func newTCPForwarder(tun *SystemTun) (*tcpForwarder, error) {
	if !tun.addr4.Next().IsValid() || !tun.addr6.Next().IsValid() {
		return nil, newError("tun cidr not large enough")
	}
	listenerConfig := &net.ListenConfig{}
	listenerConfig.SetMultipathTCP(false)
	network := "tcp"
	if !tun.enableIPv6 {
		network = "tcp4"
	}
	// IDK why but listening on 0.0.0.0 or :: rather than tun.addr4 or tun.addr6 fixes https://github.com/ExclaveNetwork/Exclave/issues/427.
	// See also https://github.com/Kr328/tun2socket/blob/dddbfaa28112d4eb1ab6a9ce0435d7f602da20d8/nat/nat.go#L20.
	listener, err := listenerConfig.Listen(context.Background(), network, ":0")
	if err != nil {
		return nil, err
	}
	addr := listener.Addr().(*net.TCPAddr)
	newError("tcp forwarder started at ", addr).AtInfo().WriteToLog()
	ctx, cancel := context.WithCancel(context.Background())
	tcpForwarder := &tcpForwarder{
		tun:       tun,
		addr4:     tun.addr4,
		addr4Next: tun.addr4.Next(),
		addr6:     tun.addr6,
		addr6Next: tun.addr6.Next(),
		port:      uint16(addr.Port),
		tcpNAT:    newTCPNAT(ctx, time.Second*300),
		listener:  listener,
		cancel:    cancel,
	}
	go tcpForwarder.dispatchLoop(listener)
	return tcpForwarder, nil
}

func (t *tcpForwarder) dispatch(listener net.Listener) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}

	ip := conn.RemoteAddr().(*net.TCPAddr).IP
	var addr netip.Addr
	if ip4 := ip.To4(); ip4 != nil {
		addr = netip.AddrFrom4([4]byte(ip4))
	} else {
		addr = netip.AddrFrom16([16]byte(ip))
	}
	if addr != t.addr4Next && addr != t.addr6Next {
		conn.Close()
		newError("unknown session with address ", addr).AtError().WriteToLog()
		return nil
	}

	port := uint16(conn.RemoteAddr().(*net.TCPAddr).Port)
	session, ok := t.tcpNAT.LookupInverse(port)
	if !ok {
		conn.Close()
		newError("unknown session with port ", port).AtError().WriteToLog()
		return nil
	}

	source := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(session.source.Addr().AsSlice()),
		Port:    v2rayNet.Port(session.source.Port()),
		Network: v2rayNet.Network_TCP,
	}
	destination := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(session.destination.Addr().AsSlice()),
		Port:    v2rayNet.Port(session.destination.Port()),
		Network: v2rayNet.Network_TCP,
	}

	go t.tun.handler.NewConnection(source, destination, conn)

	return nil
}

func (t *tcpForwarder) dispatchLoop(listener net.Listener) {
	for {
		if err := t.dispatch(listener); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				newError("dispatch tcp conn failed").Base(err).AtError().WriteToLog()
			}
			break
		}
	}
	t.cancel()
}

func (t *tcpForwarder) processIPv4(ipHdr header.IPv4, tcpHdr header.TCP) {
	source := netip.AddrPortFrom(netip.AddrFrom4(ipHdr.SourceAddress().As4()), tcpHdr.SourcePort())
	destination := netip.AddrPortFrom(netip.AddrFrom4(ipHdr.DestinationAddress().As4()), tcpHdr.DestinationPort())

	if source.Addr() == t.addr4 && source.Port() == t.port {
		session, ok := t.tcpNAT.LookupInverse(destination.Port())
		if !ok {
			newError("session not found with port: ", destination.Port()).AtError().WriteToLog()
			return
		}
		ipHdr.SetSourceAddress(tcpip.AddrFromSlice(session.destination.Addr().AsSlice()))
		tcpHdr.SetSourcePort(session.destination.Port())
		ipHdr.SetDestinationAddress(tcpip.AddrFromSlice(session.source.Addr().AsSlice()))
		tcpHdr.SetDestinationPort(session.source.Port())
	} else {
		port := t.tcpNAT.Lookup(source, destination)
		ipHdr.SetSourceAddress(tcpip.AddrFrom4(t.addr4Next.As4()))
		tcpHdr.SetSourcePort(port)
		ipHdr.SetDestinationAddress(tcpip.AddrFrom4(t.addr4.As4()))
		tcpHdr.SetDestinationPort(t.port)
	}

	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), ipHdr.PayloadLength()),
		checksum.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) processIPv6(ipHdr header.IPv6, tcpHdr header.TCP) {
	source := netip.AddrPortFrom(netip.AddrFrom16(ipHdr.SourceAddress().As16()), tcpHdr.SourcePort())
	destination := netip.AddrPortFrom(netip.AddrFrom16(ipHdr.DestinationAddress().As16()), tcpHdr.DestinationPort())

	if source.Addr() == t.addr6 && source.Port() == t.port {
		session, ok := t.tcpNAT.LookupInverse(destination.Port())
		if !ok {
			newError("session not found with port: ", destination.Port()).AtError().WriteToLog()
			return
		}
		ipHdr.SetSourceAddress(tcpip.AddrFromSlice(session.destination.Addr().AsSlice()))
		tcpHdr.SetSourcePort(session.destination.Port())
		ipHdr.SetDestinationAddress(tcpip.AddrFromSlice(session.source.Addr().AsSlice()))
		tcpHdr.SetDestinationPort(session.source.Port())
	} else {
		port := t.tcpNAT.Lookup(source, destination)
		ipHdr.SetSourceAddress(tcpip.AddrFrom16(t.addr6Next.As16()))
		tcpHdr.SetSourcePort(port)
		ipHdr.SetDestinationAddress(tcpip.AddrFrom16(t.addr6.As16()))
		tcpHdr.SetDestinationPort(t.port)
	}

	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), ipHdr.PayloadLength()),
		checksum.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) Close() error {
	_ = t.listener.Close()
	return nil
}
