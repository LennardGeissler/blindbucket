//go:build !unix

package proxy

import "syscall"

// receiveBuffer leaves the socket alone where SO_RCVBUF is not reachable
// through package syscall; the stall test is then as environment-dependent as
// it was before it existed.
func receiveBuffer(int) func(network, address string, c syscall.RawConn) error { return nil }
