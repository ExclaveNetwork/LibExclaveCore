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

package gvisor

import (
	"fmt"
	"math"
	"net"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/dyhkwong/libsagernetcore/tun"
)

func gUdpHandler(s *stack.Stack, handler tun.Handler) {
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, buffer *stack.PacketBuffer) bool {
		// Ref: gVisor pkg/tcpip/transport/udp/endpoint.go HandlePacket
		udpHdr := header.UDP(buffer.TransportHeader().View().AsSlice())
		if int(udpHdr.Length()) > buffer.Data().Size()+header.UDPMinimumSize {
			// Malformed packet.
			return true
		}
		src := v2rayNet.Destination{
			Address: v2rayNet.IPAddress(id.RemoteAddress.AsSlice()),
			Port:    v2rayNet.Port(id.RemotePort),
			Network: v2rayNet.Network_UDP,
		}
		dst := v2rayNet.Destination{
			Address: v2rayNet.IPAddress(id.LocalAddress.AsSlice()),
			Port:    v2rayNet.Port(id.LocalPort),
			Network: v2rayNet.Network_UDP,
		}
		data := buffer.Data().AsRange().ToView().AsSlice()
		packet := &gUdpPacket{
			s:                   s,
			id:                  &id,
			nicID:               buffer.NICID,
			sourceAddress:       buffer.Network().SourceAddress(),
			destinationAdddress: buffer.Network().DestinationAddress(),
			netProto:            buffer.NetworkProtocolNumber,
		}
		destUdpAddr := &net.UDPAddr{
			IP:   dst.Address.IP(),
			Port: int(dst.Port),
		}
		handler.NewPacket(src, dst, buf.FromBytes(data), func(bytes []byte, addr *net.UDPAddr) (int, error) {
			if addr == nil {
				addr = destUdpAddr
			}
			return packet.WriteBack(bytes, addr)
		})
		return true
	})
}

type gUdpPacket struct {
	s                   *stack.Stack
	id                  *stack.TransportEndpointID
	nicID               tcpip.NICID
	sourceAddress       tcpip.Address
	destinationAdddress tcpip.Address
	netProto            tcpip.NetworkProtocolNumber
}

func (p *gUdpPacket) WriteBack(b []byte, addr *net.UDPAddr) (int, error) {
	v := buffer.NewViewWithData(b)
	if v.Size() > header.UDPMaximumPacketSize {
		// Payload can't possibly fit in a packet.
		return 0, fmt.Errorf("%s", &tcpip.ErrMessageTooLong{})
	}

	var (
		localAddress tcpip.Address
		localPort    uint16
	)

	if addr == nil {
		localAddress = p.destinationAdddress
		localPort = p.id.LocalPort
	} else {
		localAddress = tcpip.AddrFromSlice(addr.IP)
		localPort = uint16(addr.Port)
	}

	route, err := p.s.FindRoute(p.nicID, localAddress, p.sourceAddress, p.netProto, false /* multicastLoop */)
	if err != nil {
		return 0, fmt.Errorf("%#v find route: %s", p.id, err)
	}
	defer route.Release()

	data := buffer.MakeWithView(v)
	if err = gSendUDP(route, data, localPort, p.id.RemotePort); err != nil {
		return 0, fmt.Errorf("%v", err)
	}
	return len(b), nil
}

// gSendUDP sends a UDP segment via the provided network endpoint and under the
// provided identity.
func gSendUDP(r *stack.Route, data buffer.Buffer, localPort, remotePort uint16) tcpip.Error {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(r.MaxHeaderLength()),
		Payload:            data,
	})
	defer pkt.DecRef()

	// Initialize the UDP header.
	udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = udp.ProtocolNumber

	length := uint16(pkt.Size())
	udpHdr.Encode(&header.UDPFields{
		SrcPort: localPort,
		DstPort: remotePort,
		Length:  length,
	})

	// Set the checksum field unless TX checksum offload is enabled.
	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	if r.RequiresTXTransportChecksum() && r.NetProto() == header.IPv6ProtocolNumber {
		xsum := udpHdr.CalculateChecksum(checksum.Combine(
			r.PseudoHeaderChecksum(udp.ProtocolNumber, length),
			pkt.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udpHdr.SetChecksum(xsum)
	}

	ttl := r.DefaultTTL()

	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: udp.ProtocolNumber,
		TTL:      ttl,
		TOS:      0, /* default */
	}, pkt); err != nil {
		r.Stats().UDP.PacketSendErrors.Increment()
		return err
	}

	// Track count of packets sent.
	r.Stats().UDP.PacketsSent.Increment()
	return nil
}
