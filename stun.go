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
	"context"
	"net"
	"net/netip"

	"github.com/exclavenetwork/go-stun/stun"

	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
)

type STUNClient interface {
	UseUDS(path string)
	UseDNSUDS(path string)
	StunTest(serverAddress string) *StunResult
	StunLegacyTest(serverAddress string) *StunLegacyResult
	StunTCPTest(serverAddress string) *StunTCPResult
}

var _ STUNClient = (*stunClient)(nil)

type stunClient struct {
	resolver *net.Resolver
	listener func(ctx context.Context, network, address string) (net.PacketConn, error)
	dialer   func(ctx context.Context, network, address string) (net.Conn, error)
}

func NewStunClient() STUNClient {
	listener := new(net.ListenConfig)
	dialer := new(net.Dialer)
	return &stunClient{
		resolver: new(net.Resolver),
		listener: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			return listener.ListenPacket(ctx, network, "[::]:0")
		},
		dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func (c *stunClient) UseUDS(path string) {
	dialer := new(net.Dialer)
	c.listener = func(ctx context.Context, network, address string) (net.PacketConn, error) {
		dest, err := v2rayNet.ParseDestination(network + ":" + address)
		if err != nil {
			return nil, err
		}
		unixConn, err := dialer.DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		packetConn := newIPCPacketConn(unixConn, dest)
		packetConn.noDomainResponse = true
		return packetConn, nil
	}
	c.dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		dest, err := v2rayNet.ParseDestination(network + ":" + address)
		if err != nil {
			return nil, err
		}
		unixConn, err := dialer.DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		return newIPCConn(unixConn, dest), nil
	}
}

func (c *stunClient) UseDNSUDS(path string) {
	dialer := new(net.Dialer)
	c.resolver.PreferGo = true
	c.resolver.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", path)
	}
}

func (c *stunClient) StunTest(serverAddress string) *StunResult {
	result := new(StunResult)
	packetConn, err := c.listen(context.Background(), serverAddress)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer packetConn.Close()
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(serverAddress)
	natBehavior, host, err := client.BehaviorTestWithAddress()
	if err != nil {
		result.Error = err.Error()
	}
	if host != nil {
		result.Host = host.String()
	}
	if natBehavior != nil {
		result.NatMapping = natBehavior.MappingType.String()
		result.NatFiltering = natBehavior.FilteringType.String()
	}
	return result
}

func (c *stunClient) StunLegacyTest(serverAddress string) *StunLegacyResult {
	result := new(StunLegacyResult)
	packetConn, err := c.listen(context.Background(), serverAddress)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer packetConn.Close()
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(serverAddress)
	natType, host, err := client.Discover()
	if err != nil {
		result.Error = err.Error()
	}
	if host != nil {
		result.Host = host.String()
	}
	if natType > 0 {
		result.NatType = natType.String()
	}
	return result
}

func (c *stunClient) StunTCPTest(serverAddress string) *StunTCPResult {
	result := new(StunTCPResult)
	conn, err := c.dial(context.Background(), serverAddress)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()
	client := stun.NewClientWithTCPConnection(conn)
	client.SetServerAddr(serverAddress)
	host, err := client.DiscoverTCP()
	if err != nil {
		result.Error = err.Error()
	}
	if host != nil {
		result.Host = host.String()
	}
	return result
}

func (c *stunClient) listen(ctx context.Context, serverAddress string) (net.PacketConn, error) {
	addr, port, err := net.SplitHostPort(serverAddress)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(serverAddress); err != nil {
		ips, err := c.resolver.LookupIP(ctx, "ip", addr)
		if err != nil {
			return nil, err
		}
		serverAddress = net.JoinHostPort(ips[0].String(), port)
	}
	return c.listener(ctx, "udp", serverAddress)
}

func (c *stunClient) dial(ctx context.Context, serverAddress string) (net.Conn, error) {
	addr, port, err := net.SplitHostPort(serverAddress)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(serverAddress); err != nil {
		ips, err := c.resolver.LookupIP(ctx, "ip", addr)
		if err != nil {
			return nil, err
		}
		serverAddress = net.JoinHostPort(ips[0].String(), port)
	}
	return c.dialer(ctx, "tcp", serverAddress)
}

type StunResult struct {
	NatMapping   string
	NatFiltering string
	Host         string
	Error        string
}

type StunLegacyResult struct {
	NatType string
	Host    string
	Error   string
}

type StunTCPResult struct {
	Host  string
	Error string
}
