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
	"container/list"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/exclavenetwork/exclave-core/v5/app/proxyman/inbound"
	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	v2log "github.com/exclavenetwork/exclave-core/v5/common/log"
	v2rayNet "github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/session"
	"github.com/exclavenetwork/exclave-core/v5/common/task"
	"github.com/exclavenetwork/exclave-core/v5/features/dns"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"

	"github.com/exclavenetwork/libexclavecore/common"
	"github.com/exclavenetwork/libexclavecore/errors"
	"github.com/exclavenetwork/libexclavecore/gvisor"
	"github.com/exclavenetwork/libexclavecore/nat"
	"github.com/exclavenetwork/libexclavecore/tun"
)

var _ tun.Handler = (*Tun2ray)(nil)

type Tun2ray struct {
	dev                 tun.Tun
	mtu                 int32
	addr4               netip.Addr
	addr6               netip.Addr
	dns4                netip.Addr
	dns6                netip.Addr
	v2ray               *V2RayInstance
	fakedns             bool
	sniffing            bool
	overrideDestination bool

	dumpUID      bool
	trafficStats bool
	pcap         bool

	udpTableMu sync.Mutex
	udpTable   map[string]*writeQueue

	appStats  sync.Map
	lockTable sync.Map

	connectionsLock sync.Mutex
	connections     list.List

	protectServer io.Closer
}

type TunConfig struct {
	FileDescriptor      int32
	Protect             bool
	Protector           Protector
	MTU                 int32
	V2Ray               *V2RayInstance
	Addr4               string
	Addr6               string
	Dns4                string
	Dns6                string
	EnableIPv6          bool
	Implementation      int32
	FakeDNS             bool
	Sniffing            bool
	OverrideDestination bool
	Debug               bool
	DumpUID             bool
	TrafficStats        bool
	PCap                bool
	ProtectPath         string
	DiscardICMP         bool

	DiscardIPv6BasedOnNetwork bool
}

func NewTun2ray(config *TunConfig) (*Tun2ray, error) {
	if config.V2Ray.localResolver == nil {
		panic("localResolver not set")
	}

	t := &Tun2ray{
		mtu:                 config.MTU,
		addr4:               netip.MustParseAddr(config.Addr4),
		addr6:               netip.MustParseAddr(config.Addr6),
		dns4:                netip.MustParseAddr(config.Dns4),
		v2ray:               config.V2Ray,
		sniffing:            config.Sniffing,
		overrideDestination: config.OverrideDestination,
		fakedns:             config.FakeDNS,
		dumpUID:             config.DumpUID,
		trafficStats:        config.TrafficStats,
		udpTable:            make(map[string]*writeQueue),
	}
	if len(config.Dns6) > 0 {
		t.dns6 = netip.MustParseAddr(config.Dns6)
	}

	discardIPv6Func := (func() bool)(nil)
	if config.DiscardIPv6BasedOnNetwork {
		discardIPv6Func = func() bool {
			return discardIPv6
		}
	}

	var err error
	switch config.Implementation {
	case common.TunImplementationGVisor:
		var pcapFile *os.File
		if config.PCap {
			timestamp := time.Now().Unix()
			path := externalAssetsPath + "pcap/" + strconv.FormatInt(timestamp, 10) + ".pcap"
			err = os.MkdirAll(filepath.Dir(path), 0o755)
			if err != nil {
				return nil, err
			}
			pcapFile, err = os.Create(path)
			if err != nil {
				return nil, err
			}
		}

		t.dev, err = gvisor.New(config.FileDescriptor, config.MTU, t, pcapFile, config.EnableIPv6, config.DiscardICMP, discardIPv6Func)
	case common.TunImplementationSystem:
		t.dev, err = nat.New(config.FileDescriptor, config.MTU, t, t.addr4, t.addr6, config.EnableIPv6, config.DiscardICMP, discardIPv6Func)
	}

	if err != nil {
		return nil, err
	}

	if !config.Protect {
		config.Protector = &noopProtector{}
	}

	if len(config.ProtectPath) > 0 {
		t.protectServer = protectServer(config.ProtectPath, config.Protector)
	}

	lookupFunc := func(network, host string) ([]net.IP, error) {
		response, err := config.V2Ray.localResolver.LookupIP(network, host)
		if err != nil {
			errStr := err.Error()
			if strings.HasPrefix(errStr, "rcode") {
				r, _ := strconv.Atoi(strings.Split(errStr, " ")[1])
				return nil, dns.RCodeError(r)
			}
			return nil, err
		}
		if response == "" {
			return nil, dns.ErrEmptyResponse
		}
		addrs := strings.Split(response, ",")
		ips := make([]net.IP, len(addrs))
		for i, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip.To4() != nil {
				ip = ip.To4()
			}
			ips[i] = ip
		}
		if len(ips) == 0 {
			return nil, dns.ErrEmptyResponse
		}
		return ips, nil
	}
	internet.UseAlternativeSystemDialer(&protectedDialer{
		protector: config.Protector,
		resolver: func(domain string) ([]net.IP, error) {
			return lookupFunc("ip", domain)
		},
	})

	return t, nil
}

func (t *Tun2ray) Close() error {
	internet.UseAlternativeSystemDialer(nil)
	common.CloseIgnore(t.dev)
	t.connectionsLock.Lock()
	for item := t.connections.Front(); item != nil; item = item.Next() {
		cancel := item.Value.(context.CancelFunc)
		cancel()
	}
	t.connectionsLock.Unlock()
	if t.protectServer != nil {
		_ = t.protectServer.Close()
	}
	return nil
}

func (t *Tun2ray) NewConnection(source v2rayNet.Destination, destination v2rayNet.Destination, conn net.Conn) {
	ib := &session.Inbound{
		Source:      source,
		Tag:         "tun",
		NetworkType: inbound.GetNetworkType(),
		SSID:        inbound.GetSSID(),
	}

	isDns := false
	if addr, err := netip.ParseAddr(destination.Address.String()); err == nil {
		isDns = addr == t.dns4 || (t.dns6.IsValid() && addr == t.dns6)
	}

	if isDns {
		if destination.Port != 53 {
			conn.Close()
			return
		}
		ib.Tag = "dns-in"
	}

	ctx := toContext(context.Background(), t.v2ray.core)
	ctx = session.ContextWithInbound(ctx, ib)
	ctx = session.ContextWithID(ctx, session.NewID())

	uid := int32(-1)
	self := false
	uidDumper, _ := inbound.GetUidDumper()
	if uidDumper != nil && (t.dumpUID || t.trafficStats) {
		var err error
		uid, err = uidDumper.DumpUid(syscall.IPPROTO_TCP, source.Address.IP().String(), int32(source.Port), destination.Address.IP().String(), int32(destination.Port))
		if err == nil {
			self = int(uid) == os.Getuid()
			if !self {
				if packageName, _ := uidDumper.GetPackageName(int32(uid)); len(packageName) == 0 {
					newError("[TCP (", uid, ")] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog(errors.ExportIDToError(ctx))
				} else {
					newError("[TCP (", uid, "/", packageName, ")] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog(errors.ExportIDToError(ctx))
				}
			}
		}
		ib.UID = uid
	}

	if !isDns && (t.sniffing || t.fakedns) {
		req := session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: t.fakedns && !t.sniffing,
			RouteOnly:    !t.overrideDestination,
		}
		if t.fakedns {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "fakedns")
		}
		if t.sniffing {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "http", "tls")
		}
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: req,
		})
	}

	var stats *appStats
	if t.trafficStats && !self {
		if iStats, exists := t.appStats.Load(uid); exists {
			stats = iStats.(*appStats)
		} else {
			iCond, loaded := t.lockTable.LoadOrStore(uid, sync.NewCond(&sync.Mutex{}))
			cond := iCond.(*sync.Cond)
			if loaded {
				cond.L.Lock()
				cond.Wait()
				iStats, exists = t.appStats.Load(uid)
				if !exists {
					panic("unexpected sync read failed")
				}
				stats = iStats.(*appStats)
				cond.L.Unlock()
			} else {
				stats = &appStats{}
				t.appStats.Store(uid, stats)
				t.lockTable.Delete(uid)
				cond.Broadcast()
			}
		}
		atomic.AddInt32(&stats.tcpConn, 1)
		atomic.AddUint32(&stats.tcpConnTotal, 1)
		atomic.StoreInt64(&stats.deactivateAt, 0)
		defer func() {
			if atomic.AddInt32(&stats.tcpConn, -1)+atomic.LoadInt32(&stats.udpConn) == 0 {
				atomic.StoreInt64(&stats.deactivateAt, time.Now().Unix())
			}
		}()
		conn = &statsConn{conn, &stats.uplink, &stats.downlink}
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	t.connectionsLock.Lock()
	elem := t.connections.PushBack(cancel)
	t.connectionsLock.Unlock()

	ctx = v2log.ContextWithAccessMessage(ctx, &v2log.AccessMessage{
		From:   source,
		To:     destination,
		Status: v2log.AccessAccepted,
	})

	proxyConn, err := t.v2ray.dial(ctx, destination)
	if err != nil {
		newError(err).AtError().WriteToLog(errors.ExportIDToError(ctx))
		return
	}
	defer common.CloseIgnore(proxyConn)
	_ = task.Run(ctx, func() error {
		_ = buf.Copy(buf.NewReader(conn), buf.NewWriter(proxyConn))
		return io.EOF
	}, func() error {
		_ = buf.Copy(buf.NewReader(proxyConn), buf.NewWriter(conn))
		return io.EOF
	})

	t.connectionsLock.Lock()
	t.connections.Remove(elem)
	t.connectionsLock.Unlock()
	common.CloseIgnore(conn)
}

type packet struct {
	data        *buf.Buffer
	destination v2rayNet.Destination
}

type writeQueue struct {
	packets chan *packet
	closed  chan struct{}
}

func (t *Tun2ray) NewPacket(source v2rayNet.Destination, destination v2rayNet.Destination, data *buf.Buffer, writeBack func([]byte, *net.UDPAddr) (int, error)) {
	natKey := source.NetAddr()

	t.udpTableMu.Lock()
	queue, loaded := t.udpTable[natKey]
	if !loaded {
		queue = &writeQueue{
			packets: make(chan *packet, 16),
			closed:  make(chan struct{}),
		}
		t.udpTable[natKey] = queue
		go t.newPacket(queue, source, destination, writeBack)
	}
	t.udpTableMu.Unlock()

	select {
	case <-queue.closed:
		data.Release()
	case queue.packets <- &packet{
		data:        data,
		destination: destination,
	}:
	}
}

func (t *Tun2ray) newPacket(queue *writeQueue, source v2rayNet.Destination, destination v2rayNet.Destination, writeBack func([]byte, *net.UDPAddr) (int, error)) {
	natKey := source.NetAddr()

	ib := &session.Inbound{
		Source:      source,
		Tag:         "tun",
		NetworkType: inbound.GetNetworkType(),
		SSID:        inbound.GetSSID(),
	}

	isDns := false
	if addr, err := netip.ParseAddr(destination.Address.String()); err == nil {
		isDns = addr == t.dns4 || (t.dns6.IsValid() && addr == t.dns6)
	}

	if isDns {
		if destination.Port != 53 {
			t.udpTableMu.Lock()
			delete(t.udpTable, natKey)
			t.udpTableMu.Unlock()
			close(queue.closed)
			return
		}
		ib.Tag = "dns-in"
	}

	ctx := toContext(context.Background(), t.v2ray.core)
	ctx = session.ContextWithInbound(ctx, ib)
	ctx = session.ContextWithID(ctx, session.NewID())

	uid := int32(-1)
	self := false
	uidDumper, _ := inbound.GetUidDumper()
	if uidDumper != nil && (t.dumpUID || t.trafficStats) {
		var err error
		uid, err = uidDumper.DumpUid(syscall.IPPROTO_UDP, source.Address.IP().String(), int32(source.Port), destination.Address.IP().String(), int32(destination.Port))
		if err == nil {
			self = int(uid) == os.Getuid()
			if !self {
				if packageName, _ := uidDumper.GetPackageName(int32(uid)); len(packageName) == 0 {
					newError("[UDP (", uid, ")] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog(errors.ExportIDToError(ctx))
				} else {
					newError("[UDP (", uid, "/", packageName, ")] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog(errors.ExportIDToError(ctx))
				}
			}
		}
		ib.UID = uid
	}

	if !isDns && (t.sniffing || t.fakedns) {
		req := session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: t.fakedns && !t.sniffing,
			RouteOnly:    !t.overrideDestination,
		}
		if t.fakedns {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "fakedns")
		}
		if t.sniffing {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "quic")
		}
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: req,
		})
	}

	ctx = v2log.ContextWithAccessMessage(ctx, &v2log.AccessMessage{
		From:   source,
		To:     destination,
		Status: v2log.AccessAccepted,
	})

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	t.connectionsLock.Lock()
	elem := t.connections.PushBack(cancel)
	t.connectionsLock.Unlock()

	conn, err := t.v2ray.dialUDP(ctx, destination, time.Second*300)
	if err != nil {
		newError(err).AtError().WriteToLog(errors.ExportIDToError(ctx))
		t.udpTableMu.Lock()
		delete(t.udpTable, natKey)
		t.udpTableMu.Unlock()
		close(queue.closed)
		return
	}

	var stats *appStats
	if t.trafficStats && !self {
		if iStats, exists := t.appStats.Load(uid); exists {
			stats = iStats.(*appStats)
		} else {
			iCond, loaded := t.lockTable.LoadOrStore(uid, sync.NewCond(&sync.Mutex{}))
			cond := iCond.(*sync.Cond)
			if loaded {
				cond.L.Lock()
				cond.Wait()
				iStats, exists = t.appStats.Load(uid)
				if !exists {
					panic("unexpected sync read failed")
				}
				stats = iStats.(*appStats)
				cond.L.Unlock()
			} else {
				stats = &appStats{}
				t.appStats.Store(uid, stats)
				t.lockTable.Delete(uid)
				cond.Broadcast()
			}
		}
		atomic.AddInt32(&stats.udpConn, 1)
		atomic.AddUint32(&stats.udpConnTotal, 1)
		atomic.StoreInt64(&stats.deactivateAt, 0)
		defer func() {
			if atomic.AddInt32(&stats.udpConn, -1)+atomic.LoadInt32(&stats.tcpConn) == 0 {
				atomic.StoreInt64(&stats.deactivateAt, time.Now().Unix())
			}
		}()
		conn = &statsPacketConn{conn, &stats.uplink, &stats.downlink}
	}

	go func() {
		for {
			select {
			case <-queue.closed:
				for packet := range queue.packets {
					packet.data.Release()
				}
				return
			case packet := <-queue.packets:
				_, err := conn.WriteTo(packet.data.Bytes(), &net.UDPAddr{
					IP:   packet.destination.Address.IP(),
					Port: int(packet.destination.Port),
				})
				packet.data.Release()
				if err != nil {
					return
				}
			}
		}
	}()

	buffer := buf.NewWithSize(t.mtu)
	for {
		buffer.Clear()
		buffer.Resize(0, t.mtu)
		n, addr, err := conn.ReadFrom(buffer.Bytes())
		if err != nil {
			break
		}
		buffer.Resize(0, int32(n))
		if addr, ok := addr.(*net.UDPAddr); ok {
			_, err = writeBack(buffer.Bytes(), addr)
		} else {
			_, err = writeBack(buffer.Bytes(), nil)
		}
		if err != nil {
			break
		}
	}
	buffer.Release()

	t.udpTableMu.Lock()
	delete(t.udpTable, natKey)
	t.udpTableMu.Unlock()
	close(queue.closed)

	t.connectionsLock.Lock()
	t.connections.Remove(elem)
	t.connectionsLock.Unlock()
	common.CloseIgnore(conn)
}
