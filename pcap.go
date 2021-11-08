package main

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

type OpenSockets map[LocalSocket]string
type Utilization map[Connection]*ConnectionInfo

type SocketFetcher interface {
	GetOpenSockets() (OpenSockets, error)
	GetProcSockets(pid int32) (OpenSockets, error)
}

var defaultDevicePrefix = []string{"en", "lo", "eth", "em", "bond"}

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

type pcapHandler struct {
	device string
	handle *pcap.Handle
}

type PcapClient struct {
	bindIPs     map[string]bool
	handlers    []pcapHandler
	bpfFilter   string
	ch          chan []Segment
	wg          sync.WaitGroup
	utilization Utilization
	utilmut     sync.Mutex
}

func NewPcapClient(bpfFilter string, devices ...string) (*PcapClient, error) {
	client := &PcapClient{
		bindIPs:     make(map[string]bool),
		handlers:    make([]pcapHandler, 0),
		ch:          make(chan []Segment, 8),
		utilization: make(Utilization),
		bpfFilter:   bpfFilter,
	}

	if err := client.getAvailableDevices(devices); err != nil {
		return nil, err
	}

	go client.consume()
	for _, handler := range client.handlers {
		go client.listen(handler)
	}

	return client, nil
}

func (c *PcapClient) getAvailableDevices(devices []string) error {
	all, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	wanted := make([]pcap.Interface, 0)
	if len(devices) > 0 {
		filter := make(map[string]struct{})
		for _, device := range devices {
			filter[device] = struct{}{}
		}
		for _, device := range all {
			_, ok := filter[device.Name]
			if !ok {
				continue
			}
			wanted = append(wanted, device)
		}
		all = wanted
	}

	if len(all) == 0 {
		return errors.New("no available devices")
	}

	for _, device := range all {
		// todo: should remove 'any' device here?
		if device.Name == "any" {
			continue
		}

		var found bool
		for _, prefix := range defaultDevicePrefix {
			if strings.HasPrefix(device.Name, prefix) {
				found = true
			}
		}
		if !found {
			continue
		}

		handler, err := c.getHandler(device.Name, c.bpfFilter)
		if err != nil {
			return err
		}
		c.handlers = append(c.handlers, pcapHandler{device: device.Name, handle: handler})
		for _, addr := range device.Addresses {
			c.bindIPs[addr.IP.String()] = true
		}
	}

	return nil
}

func (c *PcapClient) getHandler(device, bpf string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(device, 65535, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if c.bpfFilter != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			handle.Close()
			return nil, err
		}
	}

	return handle, nil
}

func (c *PcapClient) parsePort(s string) uint16 {
	idx := strings.Index(s, "(")
	if idx == -1 {
		i, _ := strconv.Atoi(s)
		return uint16(i)
	}

	i, _ := strconv.Atoi(s[:idx])
	return uint16(i)
}

func (c *PcapClient) parsePacket(device string, packet gopacket.Packet) *Segment {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ipv4pkg := ipLayer.(*layers.IPv4)
	if ipv4pkg == nil {
		return nil
	}

	var direction = DirectionDownload
	srcIP := ipv4pkg.SrcIP.String()
	dstIP := ipv4pkg.DstIP.String()
	if c.bindIPs[srcIP] {
		direction = DirectionUpload
	}

	var srcPort, dstPort uint16
	var protocol Protocol
	var dataLen int

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcpPkg, ok := tcpLayer.(*layers.TCP)
	if ok {
		srcPort = c.parsePort(tcpPkg.SrcPort.String())
		dstPort = c.parsePort(tcpPkg.DstPort.String())
		protocol = ProtoTCP
		dataLen = len(tcpPkg.Payload)
	}

	if protocol == "" {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		udpPkg, ok := udpLayer.(*layers.UDP)
		if ok {
			srcPort = c.parsePort(udpPkg.SrcPort.String())
			dstPort = c.parsePort(udpPkg.DstPort.String())
			protocol = ProtoUDP
			dataLen = len(udpPkg.Payload)
		}
	}

	// unknown packets, skip it.
	if protocol == "" {
		return nil
	}

	seg := &Segment{
		Interface: device,
		DataLen:   dataLen,
		Direction: direction,
	}

	switch seg.Direction {
	case DirectionUpload:
		seg.Connection = Connection{
			Local:  LocalSocket{IP: srcIP, Port: srcPort, Protocol: protocol},
			Remote: RemoteSocket{IP: dstIP, Port: dstPort},
		}
	case DirectionDownload:
		seg.Connection = Connection{
			Local:  LocalSocket{IP: dstIP, Port: dstPort, Protocol: protocol},
			Remote: RemoteSocket{IP: srcIP, Port: srcPort},
		}
	}

	return seg
}

func (c *PcapClient) listen(ph pcapHandler) {
	c.wg.Add(1)
	defer c.wg.Done()

	ticker := time.Tick(time.Millisecond * 100)
	const batch = 1024

	packetSource := gopacket.NewPacketSource(ph.handle, ph.handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	var segs []Segment
	for {
		select {
		case <-ticker:
			if len(segs) > 0 {
				c.ch <- segs
				segs = segs[:0]
			}

		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			seg := c.parsePacket(ph.device, packet)
			if seg != nil {
				segs = append(segs, *seg)
			}
			if len(segs) >= batch {
				c.ch <- segs
				segs = segs[:0]
			}
		}
	}
}

func (c *PcapClient) consume() {
	c.wg.Add(1)
	defer c.wg.Done()

	for segs := range c.ch {
		c.utilmut.Lock()
		for _, seg := range segs {
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
		c.utilmut.Unlock()
	}
}

func (c *PcapClient) Close() {
	for _, handler := range c.handlers {
		handler.handle.Close()
	}
	close(c.ch)
	c.wg.Wait()
}

func (c *PcapClient) GetUtilization() Utilization {
	c.utilmut.Lock()
	defer c.utilmut.Unlock()

	utilization := c.utilization
	c.utilization = make(Utilization)
	return utilization
}
