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

type Options struct {
	BPFFilter         string
	Interval          int
	ViewMode          ViewMode
	DevicesPrefix     []string
	Pids              []int
	Unit              Unit
	DisableDNSResolve bool
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
		DisableDNSResolve: false,
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
	s.pcapClient.Close()
	s.dnsResolver.Close()
	s.ui.Close()
}

func (s *Sniffer) Refresh() {
	utilization := s.pcapClient.GetUtilization()
	openSockets, err := s.socketFetcher.GetOpenSockets()
	if err != nil {
		return
	}

	s.statsManager.Put(Stat{OpenSockets: openSockets, Utilization: utilization})
	s.ui.viewer.Render(s.statsManager.GetStats())
}
