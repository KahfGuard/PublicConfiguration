//go:build !linux

package main

import "net"

func enableICMPErrors(conn net.Conn) {}
