//go:build unix

package proxy

import "syscall"

// receiveBuffer returns a dialer Control function that sets the socket's
// receive buffer before it connects, which is when the size still bounds the
// TCP window the peer is offered.
func receiveBuffer(size int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var setErr error
		if err := c.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
		}); err != nil {
			return err
		}
		return setErr
	}
}
