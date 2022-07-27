# sniffer

[![GoDoc](https://godoc.org/github.com/chenjiandongx/sniffer?status.svg)](https://godoc.org/github.com/chenjiandongx/sniffer)
[![Go Report Card](https://goreportcard.com/badge/github.com/chenjiandongx/sniffer)](https://goreportcard.com/report/github.com/chenjiandongx/sniffer)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

> *A modern alternative network traffic sniffer inspired by [bandwhich](https://github.com/imsnif/bandwhich)(Rust) and [nethogs](https://github.com/raboof/nethogs)(C++).*

https://user-images.githubusercontent.com/19553554/147360587-a3cfee18-7eb6-464b-9173-9afe6ee86cdf.mov

## Introduction

[中文介绍](https://chenjiandongx.me/2021/11/17/sniffer-network-traffic/)

sniffer is designed for network troubleshooting. It can be started at any time to analyze the processes or connections causing increases in network traffic without loading any kernel modules. By the way, the TUI of it is responsive that can fit with terminals of all sizes automatically.

sniffer manipulates [gopacket](https://github.com/google/gopacket) to sniff the interfaces and record packets' info. gopacket wraps the Golang port of `libpacp` library, and provides some additional features. One of the projects that inspired the sniffer is `bandwhich`, which has a sophisticated interface and multiple ways to display data, but it does not support BPF filters. Another one is `nethlogs`, which supports BPF filters, but can only view data by process, without connections or remote address perspective. sniffer combines the advantages of those two projects also adhering a new Plot mode.

***Connections and Process Matching***

On Linux, sniffer refers to the ways in which the [ss](https://man7.org/linux/man-pages/man8/ss.8.html) tool used, obtaining the connections of the `ESTABLISHED` state by [netlink socket](https://man7.org/linux/man-pages/man7/netlink.7.html). Since that approach is more efficient than reading the `/proc/net/*` files directly. But both need to aggregate and calculate the network traffic of the process by matching the `inode` information under `/proc/${pid}/fd`.

On macOS, the [lsof](https://ss64.com/osx/lsof.html) command is invoked, which relies on capturing the command output for analyzing process connections information. And sniffer manipulates the API provided by [gopsutil](https://github.com/shirou/gopsutil) directly on Windows.

## Installation

***sniffer*** relies on the `libpcap` library to capture user-level packets hence you need to have it installed first.

### Linux / Windows

**Debian/Ubuntu**
```shell
$ sudo apt-get install libpcap-dev
```

**CentOS/Fedora**
```shell
$ sudo yum install libpcap libpcap-devel
```

**Windows**

Windows need to have [npcap](https://nmap.org/npcap/) installed for capturing packets.

After that, install sniffer by `go get` command.

```shell
$ go get -u github.com/chenjiandongx/sniffer
```

### MacOS

```shell
$ brew install sniffer
```

## Usages

```shell
❯ sniffer -h
# A modern alternative network traffic sniffer.

Usage:
  sniffer [flags]

Examples:
  # bytes mode in MB unit
  $ sniffer -u MB

  # only capture the TCP protocol packets with lo,eth prefixed devices
  $ sniffer -b tcp -d lo -d eth

Flags:
  -a, --all-devices                  listen all devices if present
  -b, --bpf string                   specify string pcap filter with the BPF syntax (default "tcp or udp")
  -d, --devices-prefix stringArray   prefixed devices to monitor (default [en,lo,eth,em,bond])
  -h, --help                         help for sniffer
  -i, --interval int                 interval for refresh rate in seconds (default 1)
  -l, --list                         list all devices name
  -m, --mode int                     view mode of sniffer (0: bytes 1: packets 2: plot)
  -n, --no-dns-resolve               disable the DNS resolution
  -u, --unit string                  unit of traffic stats, optional: B, Kb, KB, Mb, MB, Gb, GB (default "KB")
  -v, --version                      version for sniffer
```

**Hotkeys**

| Keys | Description |
| ---- | ----------- |
| <kbd>Space</kbd> | pause refreshing |
| <kbd>Tab</kbd> | rearrange tables |
| <kbd>s</kbd> | switch next view mode |
| <kbd>q</kbd> | quit |

## Performance

[iperf](https://github.com/esnet/iperf) is a tool for active measurements of the maximum achievable bandwidth on IP networks. Next we use this tool to forge massive packets on the `lo` device.

```shell
$ iperf -s -p 5001
$ iperf -c localhost --parallel 40 -i 1 -t 2000
```

***sniffer vs bandwhich vs nethogs***

As you can see, CPU overheads `bandwhich > sniffer > nethogs`, memory overheads `sniffer > nethogs > bandwhich`.
```shell
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
 128405 root      20   0  210168   5184   3596 S  31.0   0.3   1:21.69 bandwhich
 128596 root      20   0 1449872  21912   8512 S  20.7   1.1   0:28.54 sniffer
 128415 root      20   0   18936   7464   6900 S   5.7   0.4   0:11.56 nethogs
```

See what stats they show, sniffer and bandwhich output are very approximate(~ 2.5GB/s). netlogs can only handles packets 1.122GB/s.

|  | sniffer | bandwhich | nethogs |
| -- | ------- | --------- | ------- |
| **Upload** | 2.5GiBps | 2.5GiBps | 1.12GiBps |

## View Mode

***Bytes Mode:*** display traffic stats in bytes by the Table widget.

![](https://user-images.githubusercontent.com/19553554/147360714-98709e52-1f73-4882-ba56-30f572be9b7e.jpg)

***Packets Mode:*** display traffic stats in packets by the Table widget.

![](https://user-images.githubusercontent.com/19553554/147360686-5600d65b-9685-486b-b7cf-42c341364009.jpg)

## License

MIT [©chenjiandongx](https://github.com/chenjiandongx)
