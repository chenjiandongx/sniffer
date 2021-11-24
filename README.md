# sniffer

[![GoDoc](https://godoc.org/github.com/chenjiandongx/sniffer?status.svg)](https://godoc.org/github.com/chenjiandongx/sniffer)
[![Go Report Card](https://goreportcard.com/badge/github.com/chenjiandongx/sniffer)](https://goreportcard.com/report/github.com/chenjiandongx/sniffer)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

> *A modern alternative network traffic sniffer inspired by [bandwhich](https://github.com/imsnif/bandwhich)(Rust) and [nethogs](https://github.com/raboof/nethogs)(C++).*

https://user-images.githubusercontent.com/19553554/142890205-62980e37-5861-4161-9669-737317573aa1.mov

## Introduction

[中文介绍](https://chenjiandongx.me/2021/11/17/sniffer-network-traffic/)

sniffer is designed for network troubleshooting. It can be started at any time to analyze the processes or connections causing increases in network traffic without loading any kernel modules. By the way, the TUI of it is responsive that can fit with terminals of all sizes automatically.

sniffer manipulates [gopacket](https://github.com/google/gopacket) to sniff the interfaces and record packets' info. gopacket wraps the Golang port of `libpacp` library, and provides some additional features. One of the projects that inspired the sniffer is `bandwhich`, which has a sophisticated interface and multiple ways to display data, but it does not support BPF filters. Another one is `nethlogs`, which supports BPF filters, but can only view data by process, without connections or remote address perspective. sniffer combines the advantages of those two projects also adhering a new Plot mode.

***Connections and Process Matching***

On Linux, sniffer refers to the ways in which the [ss](https://man7.org/linux/man-pages/man8/ss.8.html) tool used, obtaining the connections of the `ESTABLISHED` state by [netlink socket](https://man7.org/linux/man-pages/man7/netlink.7.html). Since that approach is more efficient than reading the `/proc/net/*` files directly. But both need to aggregate and calculate the network traffic of the process by matching the `inode` information under `/proc/${pid}/fd`.

On macOS, the [lsof](https://ss64.com/osx/lsof.html) command is invoked, which relies on capturing the command output for analyzing process connections information. And sniffer manipulates the API provided by [gopsutil](https://github.com/shirou/gopsutil) directly on Windows.

## Installation

***sniffer*** relies on the `libpcap` library to capture user-level packets hence you need to have it installed first.

**Debian/Ubuntu**
```shell
sudo apt-get install libpcap-dev
```

**CentOS/Fedora**
```shell
sudo yum install libpcap libpcap-devel
```

**MacOS**
```shell
brew install libpcap
```

**Windows**

Windows need to have [npcap](https://nmap.org/npcap/) installed for capturing packets.

After that, install sniffer by `go get` command.

```shell
go get -u github.com/chenjiandongx/sniffer
```

## Usages

```shell
❯ sniffer -h
# A modern alternative network traffic sniffer.

Usage:
  sniffer [flags]

Examples:
  # processes mode for pid 1024,2048 in MB unit
  $ sniffer -p 1024 -p 2048 -m 2 -u MB

  # only capture the TCP protocol packets with lo,eth prefixed devices
  $ sniffer -b tcp -d lo -d eth

Flags:
  -b, --bpf string                   specify string pcap filter with the BPF syntax (default "tcp or udp")
  -d, --devices-prefix stringArray   prefixed devices to monitor (default [en,lo,eth,em,bond])
  -h, --help                         help for sniffer
  -i, --interval int                 interval for refresh rate in seconds (default 1)
  -l, --list                         list all devices name
  -m, --mode int                     view mode of sniffer (0: bytes 1: packets 2: processes)
  -n, --no-dns-resolve               disable the DNS resolution
  -p, --pids int32Slice              pids to watch, empty stands for all pids (default [])
  -u, --unit string                  unit of traffic stats, optional: B, Kb, KB, Mb, MB, Gb, GB (default "KB")
  -v, --version                      version for sniffer
```

**Hotkeys**

| Keys | Description |
| ---- | ----------- |
| <kbd>Space</kbd> | pause refreshing |
| <kbd>Tab</kbd> | rearrange tables |
| <kbd>s</kbd> | switch next view mode |
| <kbd>q</kbd> / <kbd>Ctrl</kbd>+<kbd>C</kbd> | quit |

## View Mode

***Bytes Mode:*** display traffic stats in bytes by the Table widget.

![](https://user-images.githubusercontent.com/19553554/142900814-5a0d5e01-43b8-4980-85fa-e78f4a554bc6.jpg)

***Packets Mode:*** display traffic stats in packets by the Table widget.

![](https://user-images.githubusercontent.com/19553554/142900831-d7a025ad-4275-4c5f-a904-f66e329bffe7.jpg)

***Processes Mode:*** display traffic stats groups by process using Plot widget.

![](https://user-images.githubusercontent.com/19553554/142900845-50657ee0-7df6-4cca-99e8-c0fe05487b08.jpg)

## License

MIT [©chenjiandongx](https://github.com/chenjiandongx)
