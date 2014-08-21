// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mdns

// Helper routines for manipulating ip connections.

import (
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

// SetMulticastTTL sets the TTL on packets from this connection.
func SetMulticastTTL(conn *net.UDPConn, ipversion int, v int) error {
	var proto, opt int
	switch ipversion {
	default:
		proto = syscall.IPPROTO_IP
		opt = syscall.IP_MULTICAST_TTL
	case 6:
		proto = syscall.IPPROTO_IPV6
		opt = syscall.IPV6_MULTICAST_HOPS
	}
	if file, err := conn.File(); err == nil {
		fd := int(file.Fd())
		err := syscall.SetsockoptInt(fd, proto, opt, v)
		if err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
		file.Close()
	} else {
		return err
	}
	return nil
}

// SetMulticastLoopback turns on or off multicast loopbacks on the interface the connection is on.
func SetMulticastLoopback(conn *net.UDPConn, ipversion int, v bool) error {
	file, err := conn.File()
	if err != nil {
		return err
	}
	fd := int(file.Fd())
	switch ipversion {
	default:
		return setIPv4MulticastLoopback(fd, v)
	case 6:
		return setIPv6MulticastLoopback(fd, v)
	}
}
