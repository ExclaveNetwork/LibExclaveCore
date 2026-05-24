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
	"time"

	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/exclavenetwork/libexclavecore/tun"
)

func gTcpHandler(s *stack.Stack, handler tun.Handler) {
	forwarder := tcp.NewForwarder(s, 0, 1024, func(request *tcp.ForwarderRequest) {
		id := request.ID()
		waitQueue := new(waiter.Queue)
		endpoint, errT := request.CreateEndpoint(waitQueue)
		if errT != nil {
			newError("failed to create TCP connection").Base(newError(errT.String())).AtError().WriteToLog()
			// prevent potential half-open TCP connection leak.
			request.Complete(true)
			return
		}
		request.Complete(false)
		src := v2rayNet.Destination{
			Address: v2rayNet.IPAddress(id.RemoteAddress.AsSlice()),
			Port:    v2rayNet.Port(id.RemotePort),
			Network: v2rayNet.Network_TCP,
		}
		dst := v2rayNet.Destination{
			Address: v2rayNet.IPAddress(id.LocalAddress.AsSlice()),
			Port:    v2rayNet.Port(id.LocalPort),
			Network: v2rayNet.Network_TCP,
		}
		go handler.NewConnection(src, dst, gTcpConn{endpoint, gonet.NewTCPConn(waitQueue, endpoint)})
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
}

type gTcpConn struct {
	ep tcpip.Endpoint
	*gonet.TCPConn
}

func (g gTcpConn) Close() error {
	g.ep.Close()
	g.TCPConn.SetDeadline(time.Now().Add(-1))
	return g.TCPConn.Close()
}
