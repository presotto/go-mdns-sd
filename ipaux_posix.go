// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd windows

package mdns

import (
	"syscall"
)

func setIPv6MulticastLoopback(fd int, v bool) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_LOOP, boolint(v))
}
