//go:build windows
// +build windows

package main

import (
	"path/filepath"

	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

type psutilConn struct{}

func (ps *psutilConn) GetOpenSockets(pids ...int32) (OpenSockets, error) {
	return ps.getOpenSockets(pids...)
}

func (ps *psutilConn) getOpenSockets(pids ...int32) (OpenSockets, error) {
	openSockets := make(OpenSockets)
	if err := ps.getConnections(ProtoTCP, openSockets, pids...); err != nil {
		return nil, err
	}
	if err := ps.getConnections(ProtoUDP, openSockets, pids...); err != nil {
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

func (ps *psutilConn) getConnections(proto Protocol, openSockets OpenSockets, pids ...int32) error {
	connections, err := net.Connections(string(proto))
	if err != nil {
		return err
	}

	set := make(map[int32]bool)
	for _, pid := range pids {
		set[pid] = true
	}

	for _, conn := range connections {
		if proto == ProtoTCP && conn.Status != "ESTABLISHED" {
			continue
		}

		if len(pids) > 0 && !set[conn.Pid] {
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
