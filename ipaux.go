// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mdns

// Helper routines for manipulating ip connections.

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

func boolint(b bool) int {
	if b {
		return 1
	}
	return 0
}

// conn.File seems to have the effect of breaking connections, in particular,
// it seems to disable the internal timer. The problem can be seen
// in two ways depending on the version of go.
// Prior to go 1.10, a SetDeadline would have no effect on the Read calls.
// With go 1.10 and onward, calling Close blocks forever if there is an
// outstanding read when Close is called. The go 1.10+ behaviour is a
// consequence of the earlier behaviour and of the change made here:
// https://go-review.googlesource.com/c/go/+/66150.
// Mikio Hara explained this originally on grok-base,
// search for 'go-nuts-is-it-possible-to-access-sysfd-in-the-net-package'
// with sample code here:
// https://play.golang.org/p/uJo0nDaqDk - broken code
// https://play.golang.org/p/7FJ2tE_2XQ - working code
// It seems that calling conn.File() breaks the existing connection, but that
// a new connection recreated from the underlying file descriptor will
// work correctly.
func safeSetSockOpt(conn *net.UDPConn, setter func(fd int) error) (*net.UDPConn, error) {
	file, err := conn.File()
	if err != nil {
		return conn, err
	}
	if err := conn.Close(); err != nil {
		return nil, fmt.Errorf("failed to close udp conn: %v", err)
	}
	fd := int(file.Fd())
	if err := setter(fd); err != nil {
		file.Close()
		return nil, err
	}
	tmp, err := net.FileConn(file)
	file.Close()
	if conn, ok := tmp.(*net.UDPConn); ok {
		return conn, nil
	}
	return nil, fmt.Errorf("failed to recover net.UDPConn from net.Conn")
}

// SetMulticastTTL sets the TTL on packets from this connection.
func SetMulticastTTL(conn *net.UDPConn, ipversion int, v int) (*net.UDPConn, error) {
	var proto, opt int
	switch ipversion {
	default:
		proto = syscall.IPPROTO_IP
		opt = syscall.IP_MULTICAST_TTL
	case 6:
		proto = syscall.IPPROTO_IPV6
		opt = syscall.IPV6_MULTICAST_HOPS
	}
	setter := func(fd int) error {
		if err := syscall.SetsockoptInt(fd, proto, opt, v); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
		return nil
	}
	return safeSetSockOpt(conn, setter)
}

// SetMulticastLoopback turns on or off multicast loopbacks on the interface the connection is on.
func SetMulticastLoopback(conn *net.UDPConn, ipversion int, v bool) (*net.UDPConn, error) {
	setter := func(fd int) error {
		if ipversion == 6 {
			return setIPv6MulticastLoopback(fd, v)
		}
		return setIPv4MulticastLoopback(fd, v)
	}
	return safeSetSockOpt(conn, setter)
}
