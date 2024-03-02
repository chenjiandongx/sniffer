package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/gopacket/pcap"
)

type RemoteSocket struct {
	IP   string
	Port uint16
}

type LocalSocket struct {
	IP       string
	Port     uint16
	Protocol Protocol
}

type Connection struct {
	Local  LocalSocket
	Remote RemoteSocket
}

type ProcessInfo struct {
	Pid  int
	Name string
}

func (p ProcessInfo) String() string {
	return fmt.Sprintf("<%d>:%s", p.Pid, p.Name)
}

type (
	OpenSockets map[LocalSocket]ProcessInfo
	Utilization map[Connection]*ConnectionInfo
)

type SocketFetcher interface {
	GetOpenSockets() (OpenSockets, error)
}

type Protocol string

const (
	ProtoTCP Protocol = "tcp"
	ProtoUDP Protocol = "udp"
)

type Direction uint8

const (
	DirectionUpload Direction = iota
	DirectionDownload
)

type ConnectionInfo struct {
	Interface       string
	UploadPackets   int
	DownloadPackets int
	UploadBytes     int
	DownloadBytes   int
}

type Segment struct {
	Interface  string
	DataLen    int
	Connection Connection
	Direction  Direction
}

type Sinker struct {
	mut         sync.Mutex
	utilization Utilization
}

func NewSinker() *Sinker {
	return &Sinker{utilization: make(Utilization)}
}

func (c *Sinker) Fetch(seg Segment) {
	c.mut.Lock()
	defer c.mut.Unlock()

	if _, ok := c.utilization[seg.Connection]; !ok {
		c.utilization[seg.Connection] = &ConnectionInfo{
			Interface: seg.Interface,
		}
	}

	switch seg.Direction {
	case DirectionUpload:
		c.utilization[seg.Connection].UploadBytes += seg.DataLen
		c.utilization[seg.Connection].UploadPackets += 1

	case DirectionDownload:
		c.utilization[seg.Connection].DownloadBytes += seg.DataLen
		c.utilization[seg.Connection].DownloadPackets += 1
	}
}

func (c *Sinker) GetUtilization() Utilization {
	c.mut.Lock()
	defer c.mut.Unlock()

	utilization := c.utilization
	c.utilization = make(Utilization)
	return utilization
}

func ListAllDevices() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}

func listPrefixDevices(prefix []string, allowAll bool) ([]pcap.Interface, error) {
	all, err := ListAllDevices()
	if err != nil {
		return nil, err
	}

	var devs []pcap.Interface
	for _, device := range all {
		if allowAll {
			devs = append(devs, device)
			continue
		}

		for _, pre := range prefix {
			if strings.HasPrefix(device.Name, pre) {
				devs = append(devs, device)
				break
			}
		}
	}

	return devs, nil
}
