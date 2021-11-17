//go:build freebsd || darwin
// +build freebsd darwin

package main

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type lsofConn struct {
	invoker LsofInvoker
}

type LsofInvoker struct{}

func (i LsofInvoker) Exec() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "lsof", "-n", "-R", "-P", "-iTCP", "-iUDP", "-s", "TCP:ESTABLISHED", "+c", "0")

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return buf.Bytes(), err
	}

	if err := cmd.Wait(); err != nil {
		return buf.Bytes(), err
	}

	return buf.Bytes(), nil
}

func (lc *lsofConn) GetOpenSockets(pids ...int32) (OpenSockets, error) {
	sockets := make(OpenSockets)
	output, err := lc.invoker.Exec()
	if err != nil {
		return sockets, err
	}

	set := make(map[int32]bool)
	for _, pid := range pids {
		set[pid] = true
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		procName := strings.ReplaceAll(fields[0], "\\x20", " ")

		if len(pids) > 0 {
			pid, err := strconv.Atoi(fields[1])
			if err != nil {
				continue
			}
			if !set[int32(pid)] {
				continue
			}
		}

		switch fields[8] {
		case "TCP":
			addr := strings.Split(fields[9], "->")
			if len(addr) != 2 {
				continue
			}
			ipport := strings.Split(addr[0], ":")
			if len(ipport) != 2 {
				continue
			}
			port, err := strconv.Atoi(ipport[1])
			if err != nil {
				continue
			}
			sockets[LocalSocket{IP: ipport[0], Port: uint16(port), Protocol: ProtoTCP}] = procName

		case "UDP":
			ipport := strings.Split(fields[9], ":")
			if len(ipport) != 2 {
				continue
			}

			port, err := strconv.Atoi(ipport[1])
			if err != nil {
				continue
			}
			sockets[LocalSocket{IP: ipport[0], Port: uint16(port), Protocol: ProtoUDP}] = procName
		}
	}

	return sockets, nil
}

func GetSocketFetcher() SocketFetcher {
	return &lsofConn{}
}
