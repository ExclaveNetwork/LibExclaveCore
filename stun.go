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

	"github.com/exclavenetwork/go-stun/stun"

	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
)

type STUNClient interface {
	UseUDS(path string)
	UseDNSUDS(path string)
	StunNatBehaviorDiscovery(serverAddress string) *StunNatBehaviorDiscoveryResult
	StunNatTypeTest(serverAddress string) *StunNatTypeTestResult
	StunBinding(serverAddress string) *StunBindingResult
	StunTCPBinding(serverAddress string) *StunBindingResult
}

var _ STUNClient = (*stunClient)(nil)

type stunClient struct {
	resolve   *net.Resolver
	listenUDP func(ctx context.Context, dest v2rayNet.Destination) (net.PacketConn, error)
	dialTCP   func(ctx context.Context, dest v2rayNet.Destination) (net.Conn, error)
}

func NewStunClient() STUNClient {
	listener := new(net.ListenConfig)
	dialer := new(net.Dialer)
	return &stunClient{
		resolve: new(net.Resolver),
		listenUDP: func(ctx context.Context, _ v2rayNet.Destination) (net.PacketConn, error) {
			return listener.ListenPacket(ctx, "udp", "[::]:0")
		},
		dialTCP: func(ctx context.Context, dest v2rayNet.Destination) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", dest.NetAddr())
		},
	}
}

func (c *stunClient) UseUDS(path string) {
	dialer := new(net.Dialer)
	c.listenUDP = func(ctx context.Context, dest v2rayNet.Destination) (net.PacketConn, error) {
		unixConn, err := dialer.DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		packetConn := newIPCPacketConn(unixConn, dest)
		packetConn.noDomainResponse = true
		return packetConn, nil
	}
	c.dialTCP = func(ctx context.Context, dest v2rayNet.Destination) (net.Conn, error) {
		unixConn, err := dialer.DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		return newIPCConn(unixConn, dest), nil
	}
}

func (c *stunClient) UseDNSUDS(path string) {
	dialer := new(net.Dialer)
	c.resolve.PreferGo = true
	c.resolve.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", path)
	}
}

func (c *stunClient) StunNatBehaviorDiscovery(serverAddress string) *StunNatBehaviorDiscoveryResult {
	result := new(StunNatBehaviorDiscoveryResult)
	dest, err := v2rayNet.ParseDestination("udp:" + serverAddress)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if dest.Address.Family().IsDomain() {
		ips, err := c.resolve.LookupIP(context.Background(), "ip", dest.Address.Domain())
		if err != nil {
			result.Error = err.Error()
			return result
		}
		dest.Address = v2rayNet.IPAddress(ips[0])
	}
	packetConn, err := c.listenUDP(context.Background(), dest)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer packetConn.Close()
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(dest.NetAddr())
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
		if natBehavior.NoTranslation {
			result.NatMapping = natBehavior.NormalType()
		}
	}
	return result
}

func (c *stunClient) StunNatTypeTest(serverAddress string) *StunNatTypeTestResult {
	result := new(StunNatTypeTestResult)
	dest, err := v2rayNet.ParseDestination("udp:" + serverAddress)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if dest.Address.Family().IsDomain() {
		ips, err := c.resolve.LookupIP(context.Background(), "ip", dest.Address.Domain())
		if err != nil {
			result.Error = err.Error()
			return result
		}
		dest.Address = v2rayNet.IPAddress(ips[0])
	}
	packetConn, err := c.listenUDP(context.Background(), dest)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer packetConn.Close()
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(dest.NetAddr())
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

func (c *stunClient) StunBinding(serverAddress string) *StunBindingResult {
	result := new(StunBindingResult)
	dest, err := v2rayNet.ParseDestination("udp:" + serverAddress)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if dest.Address.Family().IsDomain() {
		ips, err := c.resolve.LookupIP(context.Background(), "ip", dest.Address.Domain())
		if err != nil {
			result.Error = err.Error()
			return result
		}
		dest.Address = v2rayNet.IPAddress(ips[0])
	}
	packetConn, err := c.listenUDP(context.Background(), dest)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer packetConn.Close()
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(dest.NetAddr())
	host, err := client.Binding()
	if err != nil {
		result.Error = err.Error()
	}
	if host != nil {
		result.Host = host.String()
	}
	return result
}

func (c *stunClient) StunTCPBinding(serverAddress string) *StunBindingResult {
	result := new(StunBindingResult)
	dest, err := v2rayNet.ParseDestination("tcp:" + serverAddress)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if dest.Address.Family().IsDomain() {
		ips, err := c.resolve.LookupIP(context.Background(), "ip", dest.Address.Domain())
		if err != nil {
			result.Error = err.Error()
			return result
		}
		dest.Address = v2rayNet.IPAddress(ips[0])
	}
	conn, err := c.dialTCP(context.Background(), dest)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()
	client := stun.NewClientWithTCPConnection(conn)
	client.SetServerAddr(dest.NetAddr())
	host, err := client.DiscoverTCP()
	if err != nil {
		result.Error = err.Error()
	}
	if host != nil {
		result.Host = host.String()
	}
	return result
}

type StunNatBehaviorDiscoveryResult struct {
	NatMapping   string
	NatFiltering string
	Host         string
	Error        string
}

type StunNatTypeTestResult struct {
	NatType string
	Host    string
	Error   string
}

type StunBindingResult struct {
	Host  string
	Error string
}
