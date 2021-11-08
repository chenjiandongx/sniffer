package main

import (
	"time"

	"github.com/gizak/termui/v3"
)

type options struct {
	BPFFilter     string
	RenderMode    RenderMode
	DevicesPrefix []string
}

var defaultOptions = options{
	BPFFilter:     "tcp or udp",
	RenderMode:    RModeBytes,
	DevicesPrefix: []string{"en", "lo", "eth", "em", "bond"},
}

type OptionsFn func(opt *options)

func WithBPFFilter(filter string) OptionsFn {
	return func(opt *options) {
		opt.BPFFilter = filter
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
	options       *options
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
		options:       &opts,
		dnsResolver:   dnsResolver,
		pcapClient:    pcapClient,
		statsManager:  NewStatsManager(),
		ui:            NewUIComponent(opts.RenderMode),
		socketFetcher: GetSocketFetcher(),
	}, nil
}

func (s *Sniffer) Stop() {
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

func main() {
	sniffer, err := NewSniffer()
	if err != nil {
		panic(err)
	}
	defer sniffer.Stop()

	events := termui.PollEvents()
	sniffer.Refresh()
	var paused bool

	ticker := time.Tick(time.Second)
	for {
		select {
		case e := <-events:
			switch e.ID {
			case "<Tab>":
				sniffer.ui.Shift()
			case "<Space>":
				paused = !paused
			case "<Resize>":
				payload := e.Payload.(termui.Resize)
				sniffer.ui.Resize(payload.Width, payload.Height)
			case "q", "Q", "<C-c>":
				return
			}

		case <-ticker:
			if !paused {
				sniffer.Refresh()
			}
		}
	}
}
