//go:build freebsd || darwin
// +build freebsd darwin

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type lsofConn struct {
	invoker Invoker
}

type Invoker struct{}

func (i Invoker) Command(name string, arg ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return i.CommandWithContext(ctx, name, arg...)
}

func (i Invoker) CommandWithContext(ctx context.Context, name string, arg ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, arg...)

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

func (lc *lsofConn) GetProcSockets(pid int32) (OpenSockets, error) { return nil, nil }

func (lc *lsofConn) GetOpenSockets() (OpenSockets, error) {
	sockets := make(OpenSockets)
	output, err := lc.invoker.Command("lsof", "-n", "-P", "-iTCP", "-iUDP", "-s", "TCP:ESTABLISHED", "+c", "0")
	if err != nil {
		fmt.Println(err)
		return sockets, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		procName := strings.ReplaceAll(fields[0], "\\x20", " ")

		switch fields[7] {
		case "TCP":
			addr := strings.Split(fields[8], "->")
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
			ipport := strings.Split(fields[8], ":")
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
