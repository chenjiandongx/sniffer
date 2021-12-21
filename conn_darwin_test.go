package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type noopInvoker struct{}

func (noopInvoker) Exec() ([]byte, error) {
	output := `
goland                          44546     1 chenjiandongx   14u  IPv4 0x22b93638598dd98d      0t0  UDP *:60203
goland                          44546     1 chenjiandongx   17u  IPv4 0x22b93638598dfb3d      0t0  UDP *:8976
wget                            44817 44815 chenjiandongx   19u  IPv4 0x22b9363883c47b35      0t0  TCP 127.0.0.1:53747->127.0.0.1:49152 (ESTABLISHED)`
	return []byte(output), nil

}

func TestDarwinGetSockets(t *testing.T) {
	conn := lsofConn{invoker: noopInvoker{}}
	sockets, err := conn.GetOpenSockets()
	assert.NoError(t, err)

	expected := map[LocalSocket]ProcessInfo{
		{IP: "*", Port: 8976, Protocol: ProtoUDP}:          {Pid: 44546, Name: "goland"},
		{IP: "*", Port: 60203, Protocol: ProtoUDP}:         {Pid: 44546, Name: "goland"},
		{IP: "127.0.0.1", Port: 53747, Protocol: ProtoTCP}: {Pid: 44817, Name: "wget"},
	}

	assert.Equal(t, OpenSockets(expected), sockets)
}
