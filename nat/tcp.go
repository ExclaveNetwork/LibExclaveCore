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

package nat

import (
	"context"
	"errors"
	"net"
	"time"

	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/exclavenetwork/libexclavecore/common"
)

type tcpForwarder struct {
	tun      *SystemTun
	port     uint16
	listener *net.TCPListener
	sessions *common.LruCache
}

func newTcpForwarder(tun *SystemTun) (*tcpForwarder, error) {
	tcpForwarder := &tcpForwarder{
		tun:      tun,
		sessions: common.NewLruCache(300, true),
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
	tcpForwarder.listener = listener.(*net.TCPListener)
	tcpForwarder.port = uint16(listener.Addr().(*net.TCPAddr).Port)
	newError("tcp forwarder started at ", listener.Addr().(*net.TCPAddr)).AtInfo().WriteToLog()
	return tcpForwarder, nil
}

func (t *tcpForwarder) dispatch(listener *net.TCPListener) error {
	conn, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	addr := conn.RemoteAddr().(*net.TCPAddr)
	var ip net.IP
	if ip4 := addr.IP.To4(); ip4 != nil {
		ip = ip4
	} else {
		ip = addr.IP
	}
	key := peerKey{
		destinationAddress: tcpip.AddrFromSlice(ip),
		sourcePort:         uint16(addr.Port),
	}
	var session *peerValue
	iSession, ok := t.sessions.Get(key)
	if ok {
		session = iSession.(*peerValue)
	} else {
		conn.Close()
		newError("dropped unknown tcp session with source port ", key.sourcePort, " to destination address ", key.destinationAddress).AtWarning().WriteToLog()
		return nil
	}

	source := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(session.sourceAddress.AsSlice()),
		Port:    v2rayNet.Port(key.sourcePort),
		Network: v2rayNet.Network_TCP,
	}
	destination := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(key.destinationAddress.AsSlice()),
		Port:    v2rayNet.Port(session.destinationPort),
		Network: v2rayNet.Network_TCP,
	}

	go func() {
		t.tun.handler.NewConnection(source, destination, conn)
		time.Sleep(time.Second * 5)
		t.sessions.Delete(key)
	}()

	return nil
}

func (t *tcpForwarder) dispatchLoop(listener *net.TCPListener) {
	for {
		if err := t.dispatch(listener); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				newError("dispatch tcp conn failed").Base(err).AtError().WriteToLog()
			}
			break
		}
	}
}

func (t *tcpForwarder) processIPv4(ipHdr header.IPv4, tcpHdr header.TCP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := tcpHdr.SourcePort()
	destinationPort := tcpHdr.DestinationPort()

	var session *peerValue

	if sourcePort != t.port {
		key := peerKey{
			destinationAddress: destinationAddress,
			sourcePort:         sourcePort,
		}
		iSession, ok := t.sessions.Get(key)
		if ok {
			session = iSession.(*peerValue)
		} else {
			session = &peerValue{sourceAddress, destinationPort}
			t.sessions.Set(key, session)
		}
		ipHdr.SetSourceAddress(destinationAddress)
		ipHdr.SetDestinationAddress(tcpip.AddrFrom4(t.tun.addr4.As4()))
		tcpHdr.SetDestinationPort(t.port)
	} else {
		key := peerKey{
			destinationAddress: destinationAddress,
			sourcePort:         destinationPort,
		}
		iSession, ok := t.sessions.Get(key)
		if ok {
			session = iSession.(*peerValue)
		} else {
			newError("unknown tcp session with source port ", destinationPort, " to destination address ", destinationAddress).AtWarning().WriteToLog()
			return
		}
		ipHdr.SetSourceAddress(destinationAddress)
		tcpHdr.SetSourcePort(session.destinationPort)
		ipHdr.SetDestinationAddress(session.sourceAddress)
	}

	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), uint16(len(tcpHdr))),
		checksum.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) processIPv6(ipHdr header.IPv6, tcpHdr header.TCP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := tcpHdr.SourcePort()
	destinationPort := tcpHdr.DestinationPort()

	var session *peerValue

	if sourcePort != t.port {
		key := peerKey{
			destinationAddress: destinationAddress,
			sourcePort:         destinationPort,
		}
		iSession, ok := t.sessions.Get(key)
		if ok {
			session = iSession.(*peerValue)
		} else {
			session = &peerValue{
				sourceAddress:   sourceAddress,
				destinationPort: destinationPort,
			}
			t.sessions.Set(key, session)
		}

		ipHdr.SetSourceAddress(destinationAddress)
		ipHdr.SetDestinationAddress(tcpip.AddrFrom16(t.tun.addr6.As16()))
		tcpHdr.SetDestinationPort(t.port)
	} else {
		key := peerKey{
			destinationAddress: destinationAddress,
			sourcePort:         destinationPort,
		}
		iSession, ok := t.sessions.Get(key)
		if ok {
			session = iSession.(*peerValue)
		} else {
			newError("unknown tcp session with source port ", destinationPort, " to destination address ", destinationAddress).AtWarning().WriteToLog()
			return
		}

		ipHdr.SetSourceAddress(destinationAddress)
		tcpHdr.SetSourcePort(session.destinationPort)
		ipHdr.SetDestinationAddress(session.sourceAddress)
	}

	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), uint16(len(tcpHdr))),
		checksum.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) Close() error {
	_ = t.listener.Close()
	return nil
}
