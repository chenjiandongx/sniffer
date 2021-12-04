package main

import (
	"fmt"
	"os"
	"time"

	"github.com/gizak/termui/v3"
)

func exit(s string) {
	fmt.Println("Start sniffer failed:", s)
	os.Exit(1)
}

// Options is the options set for the sniffer instance.
type Options struct {
	// BPFFilter is the string pcap filter with the BPF syntax
	// eg. "tcp and port 80"
	BPFFilter string

	// Interval is the interval for refresh rate in seconds
	Interval int

	// ViewMode represents the sniffer view mode, optional: bytes, packets, processes
	ViewMode ViewMode

	// DevicesPrefix represents prefixed devices to monitor
	DevicesPrefix []string

	// Pids to watch in processes mode
	Pids []int32

	// Unit of stats in processes mode, optional: B, Kb, KB, Mb, MB, Gb, GB
	Unit Unit

	// DisableDNSResolve decides whether if disable the DNS resolution
	DisableDNSResolve bool

	// AllDevices specifies whether to listen all devices or not
	AllDevices bool
}

func (o Options) Validate() error {
	if err := o.ViewMode.Validate(); err != nil {
		return err
	}
	if err := o.Unit.Validate(); err != nil {
		return err
	}
	return nil
}

func DefaultOptions() Options {
	return Options{
		BPFFilter:         "tcp or udp",
		Interval:          1,
		ViewMode:          ModeTableBytes,
		Unit:              UnitKB,
		DevicesPrefix:     []string{"en", "lo", "eth", "em", "bond"},
		DisableDNSResolve: false,
		AllDevices:        false,
	}
}

type Sniffer struct {
	opts          Options
	dnsResolver   *DNSResolver
	pcapClient    *PcapClient
	statsManager  *StatsManager
	ui            *UIComponent
	socketFetcher SocketFetcher
}

func NewSniffer(opts Options) (*Sniffer, error) {
	dnsResolver := NewDnsResolver()
	pcapClient, err := NewPcapClient(dnsResolver.Lookup, opts)
	if err != nil {
		return nil, err
	}

	return &Sniffer{
		opts:          opts,
		dnsResolver:   dnsResolver,
		pcapClient:    pcapClient,
		statsManager:  NewStatsManager(opts),
		ui:            NewUIComponent(opts),
		socketFetcher: GetSocketFetcher(),
	}, nil
}

func (s *Sniffer) SwitchViewMode() {
	s.opts.ViewMode = (s.opts.ViewMode + 1) % 3
	s.statsManager = NewStatsManager(s.opts)

	s.ui.Close()
	s.ui = NewUIComponent(s.opts)
}

func (s *Sniffer) Start() {
	events := termui.PollEvents()
	s.Refresh()
	var paused bool

	ticker := time.Tick(time.Duration(s.opts.Interval) * time.Second)
	for {
		select {
		case e := <-events:
			switch e.ID {
			case "<Tab>":
				s.ui.viewer.Shift()
			case "<Space>":
				paused = !paused
			case "<Resize>":
				payload := e.Payload.(termui.Resize)
				s.ui.viewer.Resize(payload.Width, payload.Height)
			case "s", "S":
				s.SwitchViewMode()
			case "q", "Q", "<C-c>":
				return
			}

		case <-ticker:
			if !paused {
				s.Refresh()
			}
		}
	}
}

func (s *Sniffer) Close() {
	s.ui.Close()
	s.pcapClient.Close()
	s.dnsResolver.Close()
}

func (s *Sniffer) Refresh() {
	utilization := s.pcapClient.sinker.GetUtilization()
	openSockets, err := s.socketFetcher.GetOpenSockets(s.opts.Pids...)
	if err != nil {
		return
	}

	s.statsManager.Put(Stat{OpenSockets: openSockets, Utilization: utilization})
	s.ui.viewer.Render(s.statsManager.GetStats())
}
