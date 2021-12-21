//go:build linux
// +build linux

package main

import (
	"context"
	"errors"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

type pcapHandler struct {
	device string
	handle *afpacket.TPacket
}

type PcapClient struct {
	ctx               context.Context
	cancel            context.CancelFunc
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
		sinker:            NewSinker(),
		lookup:            lookup,
		bpfFilter:         opt.BPFFilter,
		devicesPrefix:     opt.DevicesPrefix,
		disableDNSResolve: opt.DisableDNSResolve,
		allDevices:        opt.AllDevices,
	}

	client.ctx, client.cancel = context.WithCancel(context.Background())
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
		handler, err := c.getHandler(device.Name)
		if err != nil {
			continue
		}

		if c.bpfFilter != "" {
			if err = c.setBPFFilter(handler, c.bpfFilter); err != nil {
				continue
			}
		}

		c.handlers = append(c.handlers, &pcapHandler{device: device.Name, handle: handler})
		for _, addr := range device.Addresses {
			c.bindIPs[addr.IP.String()] = true
		}
	}

	if len(c.handlers) == 0 {
		return errors.New("no available devices found")
	}
	return nil
}

func (c *PcapClient) getHandler(device string) (*afpacket.TPacket, error) {
	return afpacket.NewTPacket(afpacket.OptInterface(device))
}

func (c *PcapClient) setBPFFilter(h *afpacket.TPacket, filter string) error {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, filter)
	if err != nil {
		return err
	}
	var bpfIns []bpf.RawInstruction
	for _, ins := range pcapBPF {
		bpfIns = append(bpfIns, bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		})
	}
	return h.SetBPF(bpfIns)
}

func (c *PcapClient) parsePacket(ph *pcapHandler, decoded []gopacket.Layer) *Segment {
	var srcPort, dstPort uint16
	var srcIP, dstIP string
	var protocol Protocol
	var dataLen int
	direction := DirectionDownload

	for _, layerType := range decoded {
		switch lyr := layerType.(type) {
		case *layers.IPv4:
			srcIP = lyr.SrcIP.String()
			dstIP = lyr.DstIP.String()
			if c.bindIPs[srcIP] {
				direction = DirectionUpload
			}

		case *layers.IPv6:
			srcIP = lyr.SrcIP.String()
			dstIP = lyr.DstIP.String()
			if c.bindIPs[srcIP] {
				direction = DirectionUpload
			}

		case *layers.TCP:
			protocol = ProtoTCP
			srcPort = parsePort(lyr.SrcPort.String())
			dstPort = parsePort(lyr.DstPort.String())
			dataLen = len(lyr.Contents) + len(lyr.Payload)

		case *layers.UDP:
			protocol = ProtoUDP
			srcPort = parsePort(lyr.SrcPort.String())
			dstPort = parsePort(lyr.DstPort.String())
			dataLen = len(lyr.Contents) + len(lyr.Payload)
		}
	}

	if protocol == "" {
		return nil
	}

	seg := &Segment{
		Interface: ph.device,
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

	decoded := make([]gopacket.Layer, 0, 2)
	var payload []byte
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6

	for {
		select {
		case <-c.ctx.Done():
			return

		default:
			decoded = decoded[:0]
			payload = payload[:0]
			pkt, _, err := ph.handle.ZeroCopyReadPacketData()
			if err != nil {
				continue
			}

			var ether layers.Ethernet
			if err = ether.DecodeFromBytes(pkt, gopacket.NilDecodeFeedback); err != nil {
				continue
			}

			if ether.EthernetType != layers.EthernetTypeIPv4 {
				continue
			}

			if err = ipv4.DecodeFromBytes(ether.Payload, gopacket.NilDecodeFeedback); err == nil {
				payload = ipv4.Payload
				decoded = append(decoded, &ipv4)
			}
			if len(payload) == 0 {
				if err = ipv6.DecodeFromBytes(ether.Payload, gopacket.NilDecodeFeedback); err == nil {
					payload = ipv6.Payload
					decoded = append(decoded, &ipv6)
				}
			}

			if len(decoded) == 0 {
				continue
			}

			var tcpPkg layers.TCP
			if err = tcpPkg.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err == nil {
				decoded = append(decoded, &tcpPkg)
				seg := c.parsePacket(ph, decoded)
				if seg != nil {
					c.sinker.Fetch(*seg)
				}
				continue
			}

			var udpPkg layers.UDP
			if err = udpPkg.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err == nil {
				decoded = append(decoded, &udpPkg)
				seg := c.parsePacket(ph, decoded)
				if seg != nil {
					c.sinker.Fetch(*seg)
				}
			}
		}
	}
}

func (c *PcapClient) Close() {
	c.cancel()
	c.wg.Wait()

	for _, handler := range c.handlers {
		handler.handle.Close()
	}
}
