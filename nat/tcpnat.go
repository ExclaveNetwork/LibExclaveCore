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
	"net/netip"
	"sync"
	"time"
)

type tcpNAT struct {
	timeout    time.Duration
	portIndex  uint16
	portAccess sync.RWMutex
	addrAccess sync.RWMutex
	addrMap    map[natKey]uint16
	portMap    map[uint16]*session
}

type natKey struct {
	source      netip.AddrPort
	destination netip.AddrPort
}

type session struct {
	sync.Mutex
	source      netip.AddrPort
	destination netip.AddrPort
	lastActive  time.Time
}

func newTCPNAT(ctx context.Context, timeout time.Duration) *tcpNAT {
	tcpNAT := &tcpNAT{
		timeout:   timeout,
		portIndex: 10000,
		addrMap:   make(map[natKey]uint16),
		portMap:   make(map[uint16]*session),
	}
	go tcpNAT.loopCheckTimeout(ctx)
	return tcpNAT
}

func (n *tcpNAT) loopCheckTimeout(ctx context.Context) {
	ticker := time.NewTicker(n.timeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.checkTimeout()
		case <-ctx.Done():
			return
		}
	}
}

func (n *tcpNAT) checkTimeout() {
	now := time.Now()
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	for natPort, session := range n.portMap {
		session.Lock()
		if now.Sub(session.lastActive) > n.timeout {
			delete(n.addrMap, natKey{source: session.source, destination: session.destination})
			delete(n.portMap, natPort)
		}
		session.Unlock()
	}
}

func (n *tcpNAT) LookupInverse(port uint16) (*session, bool) {
	n.portAccess.RLock()
	session, ok := n.portMap[port]
	n.portAccess.RUnlock()
	if ok {
		session.Lock()
		if time.Since(session.lastActive) > time.Second {
			session.lastActive = time.Now()
		}
		session.Unlock()
	}
	return session, ok
}

func (n *tcpNAT) Lookup(source netip.AddrPort, destination netip.AddrPort) uint16 {
	key := natKey{
		source:      source,
		destination: destination,
	}
	n.addrAccess.RLock()
	port, loaded := n.addrMap[key]
	n.addrAccess.RUnlock()
	if loaded {
		return port
	}
	n.addrAccess.Lock()
	nextPort := n.portIndex
	if nextPort == 0 {
		nextPort = 10000
		n.portIndex = 10001
	} else {
		n.portIndex++
	}
	n.addrMap[key] = nextPort
	n.addrAccess.Unlock()
	n.portAccess.Lock()
	n.portMap[nextPort] = &session{
		source:      source,
		destination: destination,
		lastActive:  time.Now(),
	}
	n.portAccess.Unlock()
	return nextPort
}
