//go:build !linux
// +build !linux

package main

import (
	"errors"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type pcapHandler struct {
	device string
	handle *pcap.Handle
}

type PcapClient struct {
	bindIPs           map[string]bool
	handlers          []*pcapHandler
	bpfFilter         string
	sinker            *Sinker
	devicesPrefix     []string
	disableDNSResolve bool
	allDevices        bool
	wg                sync.WaitGroup
	lookup            Lookup
}

func NewPcapClient(lookup Lookup, opt Options) (*PcapClient, error) {
	client := &PcapClient{
		bindIPs:           make(map[string]bool),
		handlers:          make([]*pcapHandler, 0),
		sinker:            NewSinker(),
		lookup:            lookup,
		bpfFilter:         opt.BPFFilter,
		devicesPrefix:     opt.DevicesPrefix,
		disableDNSResolve: opt.DisableDNSResolve,
		allDevices:        opt.AllDevices,
	}

	if err := client.getAvailableDevices(); err != nil {
		return nil, err
	}

	for _, handler := range client.handlers {
		go client.listen(handler)
	}

	return client, nil
}

func (c *PcapClient) getAvailableDevices() error {
	devs, err := listPrefixDevices(c.devicesPrefix, c.allDevices)
	if err != nil {
		return err
	}

	for _, device := range devs {
		handler, err := c.getHandler(device.Name, c.bpfFilter)
		if err != nil {
			continue
		}
		c.handlers = append(c.handlers, &pcapHandler{
			device: device.Name,
			handle: handler,
		})
		for _, addr := range device.Addresses {
			c.bindIPs[addr.IP.String()] = true
		}
	}

	if len(c.handlers) == 0 {
		return errors.New("no available devices found")
	}

	return nil
}

func (c *PcapClient) getHandler(device, filter string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(device, 65535, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if c.bpfFilter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, err
		}
	}

	return handle, nil
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

	direction := DirectionDownload
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
		srcPort = uint16(tcpPkg.SrcPort)
		dstPort = uint16(tcpPkg.DstPort)
		protocol = ProtoTCP
		dataLen = len(tcpPkg.Contents) + len(tcpPkg.Payload)
	}

	if protocol == "" {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		udpPkg, ok := udpLayer.(*layers.UDP)
		if ok {
			srcPort = uint16(udpPkg.SrcPort)
			dstPort = uint16(udpPkg.DstPort)
			protocol = ProtoUDP
			dataLen = len(udpPkg.Contents) + len(udpPkg.Payload)
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

	var remoteIP string
	switch seg.Direction {
	case DirectionUpload:
		remoteIP = dstIP
		if protocol == ProtoTCP && !c.disableDNSResolve {
			remoteIP = c.lookup(dstIP)
		}
		seg.Connection = Connection{
			Local:  LocalSocket{IP: srcIP, Port: srcPort, Protocol: protocol},
			Remote: RemoteSocket{IP: remoteIP, Port: dstPort},
		}

	case DirectionDownload:
		remoteIP = srcIP
		if protocol == ProtoTCP && !c.disableDNSResolve {
			remoteIP = c.lookup(srcIP)
		}
		seg.Connection = Connection{
			Local:  LocalSocket{IP: dstIP, Port: dstPort, Protocol: protocol},
			Remote: RemoteSocket{IP: remoteIP, Port: srcPort},
		}
	}

	return seg
}

func (c *PcapClient) listen(ph *pcapHandler) {
	c.wg.Add(1)
	defer c.wg.Done()

	packetSource := gopacket.NewPacketSource(ph.handle, ph.handle.LinkType())
	packetSource.Lazy = true
	packetSource.NoCopy = true

	for {
		select {
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			seg := c.parsePacket(ph.device, packet)
			if seg == nil {
				continue
			}
			c.sinker.Fetch(*seg)
		}
	}
}

func (c *PcapClient) Close() {
	for _, handler := range c.handlers {
		handler.handle.Close()
	}
	c.wg.Wait()
}
