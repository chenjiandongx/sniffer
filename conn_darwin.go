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
	invoker Invoker
}

type Invoker interface {
	Exec() ([]byte, error)
}

type lsofInvoker struct{}

// Exec executes the command and return the output bytes of it.
func (i lsofInvoker) Exec() ([]byte, error) {
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

func (lc *lsofConn) GetOpenSockets() (OpenSockets, error) {
	sockets := make(OpenSockets)
	output, err := lc.invoker.Exec()
	if err != nil {
		return sockets, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		procName := strings.ReplaceAll(fields[0], "\\x20", " ")
		pid, _ := strconv.Atoi(fields[1])
		procInfo := ProcessInfo{Pid: pid, Name: procName}

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
			sockets[LocalSocket{IP: ipport[0], Port: uint16(port), Protocol: ProtoTCP}] = procInfo

		case "UDP":
			ipport := strings.Split(fields[9], ":")
			if len(ipport) != 2 {
				continue
			}

			port, err := strconv.Atoi(ipport[1])
			if err != nil {
				continue
			}
			sockets[LocalSocket{IP: ipport[0], Port: uint16(port), Protocol: ProtoUDP}] = procInfo
		}
	}

	return sockets, nil
}

func GetSocketFetcher() SocketFetcher {
	return &lsofConn{invoker: lsofInvoker{}}
}
