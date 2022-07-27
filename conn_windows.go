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

func (ps *psutilConn) getProcName(pid int32) ProcessInfo {
	procInfo := ProcessInfo{Name: unknownProcessName}

	proc, err := process.NewProcess(pid)
	if err != nil {
		return procInfo
	}
	exe, err := proc.Exe()
	if err != nil {
		return procInfo
	}

	procInfo.Pid = int(pid)
	procInfo.Name = filepath.Base(exe)
	return procInfo
}

func (ps *psutilConn) getConnections(proto Protocol, openSockets OpenSockets) error {
	connections, err := net.Connections(string(proto))
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
	return nil
}

func GetSocketFetcher() SocketFetcher {
	return &psutilConn{}
}
