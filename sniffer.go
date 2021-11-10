package main

import (
	"time"

	"github.com/gizak/termui/v3"
)

type options struct {
	BPFFilter     string
	Interval      int
	RenderMode    RenderMode
	DevicesPrefix []string
}

var defaultOptions = options{
	BPFFilter:     "tcp or udp",
	Interval:      1,
	RenderMode:    RModeBytes,
	DevicesPrefix: []string{"en", "lo", "eth", "em", "bond"},
}

type OptionsFn func(opt *options)

func WithBPFFilter(filter string) OptionsFn {
	return func(opt *options) {
		opt.BPFFilter = filter
	}
}

func WithInterval(interval int) OptionsFn {
	return func(opt *options) {
		opt.Interval = interval
	}
}

func WithRenderMode(mode RenderMode) OptionsFn {
	return func(opt *options) {
		opt.RenderMode = mode
	}
}

func WithDevicesPrefix(devicesPrefix []string) OptionsFn {
	return func(opt *options) {
		opt.DevicesPrefix = devicesPrefix
	}
}

type Sniffer struct {
	opts          *options
	dnsResolver   *DNSResolver
	pcapClient    *PcapClient
	statsManager  *StatsManager
	ui            *UIComponent
	socketFetcher SocketFetcher
}

func NewSniffer(fn ...OptionsFn) (*Sniffer, error) {
	opts := defaultOptions
	for _, f := range fn {
		f(&opts)
	}
	dnsResolver := NewDnsResolver()
	pcapClient, err := NewPcapClient(dnsResolver.Lookup, opts.BPFFilter, opts.DevicesPrefix)
	if err != nil {
		return nil, err
	}

	return &Sniffer{
		opts:          &opts,
		dnsResolver:   dnsResolver,
		pcapClient:    pcapClient,
		statsManager:  NewStatsManager(opts.Interval, opts.RenderMode),
		ui:            NewUIComponent(opts.RenderMode),
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
				s.ui.Shift()
			case "<Space>":
				paused = !paused
			case "<Resize>":
				payload := e.Payload.(termui.Resize)
				s.ui.Resize(payload.Width, payload.Height)
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
	termui.Close()
}

func (s *Sniffer) Refresh() {
	utilization := s.pcapClient.GetUtilization()
	openSockets, err := s.socketFetcher.GetOpenSockets()
	if err != nil {
		return
	}

	s.statsManager.Put(Stat{OpenSockets: openSockets, Utilization: utilization})
	s.ui.Render(s.statsManager.GetSnapshot())
}
