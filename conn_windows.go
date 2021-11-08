//go:build windows
// +build windows

package main

import (
	"path/filepath"

	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

type psutilConn struct{}

func (ps *psutilConn) GetOpenSockets() (OpenSockets, error) {
	openSockets := make(OpenSockets)
	if err := ps.getConnections(ProtoTCP, openSockets); err != nil {
		return nil, err
	}
	if err := ps.getConnections(ProtoUDP, openSockets); err != nil {
		return nil, err
	}

	return openSockets, nil
}

func (ps *psutilConn) GetProcSockets(pid int32) (OpenSockets, error) { return nil, nil }

func (ps *psutilConn) getProcName(pid int32) string {
	proc, err := process.NewProcess(pid)
	if err != nil {
		return unknownProcessName
	}
	exe, err := proc.Exe()
	if err != nil {
		return unknownProcessName
	}
	return filepath.Base(exe)
}

func (ps *psutilConn) getConnections(proto Protocol, openSockets OpenSockets) error {
	protos := []string{"tcp", "tcp6"}
	if proto == ProtoUDP {
		protos = []string{"udp", "udp6"}
	}

	for _, p := range protos {
		connections, err := net.Connections(p)
		if err != nil {
			return err
		}

		for _, conn := range connections {
			if proto == ProtoTCP && conn.Status != "ESTABLISHED" {
				continue
			}

			localSocket := LocalSocket{
				IP:       conn.Laddr.IP,
				Port:     uint16(conn.Laddr.Port),
				Protocol: proto,
			}
			openSockets[localSocket] = ps.getProcName(conn.Pid)
		}
	}
	return nil
}

func GetSocketFetcher() SocketFetcher {
	return &psutilConn{}
}
