package main

import (
	"github.com/spf13/cobra"
)

func NewApp() *cobra.Command {
	defaultOpts := DefaultOptions()

	opt := Options{}
	var mode int
	var unit string

	app := &cobra.Command{
		Use:     "sniffer",
		Short:   "# A modern alternative network traffic sniffer.",
		Version: "v0.1.0",
		Run: func(cmd *cobra.Command, args []string) {
			opt.ViewMode = ViewMode(mode)
			opt.Unit = Unit(unit)
			if err := opt.Validate(); err != nil {
				exit(err.Error())
			}

			sniffer, err := NewSniffer(opt)
			if err != nil {
				exit(err.Error())
			}
			defer sniffer.Close()
			sniffer.Start()
		},
		Example: `  # processes mode for pid 1024,2048 in MB unit
  $ sniffer -p 1024 -p 2048 -m 2 -u MB

  # only capture the TCP protocol packets with lo,eth prefixed devices
  $ sniffer -b tcp -d lo -d eth`,
	}

	app.Flags().StringVarP(&opt.BPFFilter, "bpf", "b", defaultOpts.BPFFilter, "specify string pcap filter with the BPF syntax")
	app.Flags().IntVarP(&opt.Interval, "interval", "i", defaultOpts.Interval, "interval for refresh rate in seconds")
	app.Flags().StringArrayVarP(&opt.DevicesPrefix, "devices-prefix", "d", defaultOpts.DevicesPrefix, "prefixed devices to monitor (default: any devices)")
	app.Flags().BoolVarP(&opt.DisableDNSResolve, "no-dns-resolve", "n", defaultOpts.DisableDNSResolve, "disable the DNS resolution")
	app.Flags().IntSliceVarP(&opt.Pids, "pids", "p", defaultOpts.Pids, "pids to watch in processes mode (default all processes)")
	app.Flags().IntVarP(&mode, "mode", "m", int(defaultOpts.ViewMode), "view mode of sniffer (0: bytes 1: packets 2: processes)")
	app.Flags().StringVarP(&unit, "unit", "u", defaultOpts.Unit.String(), "unit of traffic stats in processes mode, optional: B, KB, MB, GB")

	return app
}

func main() {
	app := NewApp()
	if err := app.Execute(); err != nil {
		exit(err.Error())
	}
}
