# sniffer

> 🐶 *A modern alternative network traffic sniffer inspired by [bandwhich](https://github.com/imsnif/bandwhich)(Rust) and [nethogs](https://github.com/raboof/nethogs)(C++).*

https://user-images.githubusercontent.com/19553554/141692419-da8b63e1-e936-4d14-8ff5-5893e20a1f27.mov

## Introduction

sniffer is designed for network troubleshooting. It can be started at any time to analyze the processes or connections causing increases in network traffic without loading any kernel modules. In addition, the GUI of it is responsive that can fit with terminals of all sizes automatically.

sniffer manipulates [gopacket](https://github.com/google/gopacket) to sniff the interfaces and record packets' info. gopacket wraps the Golang port of `libpacp` library, and provides some additional features. One of the projects that inspired the sniffer is `bandwhich`, which has a sophisticated interface and multiple ways to display data, but it does not support BPF filters. Another one is `nethlogs`, which supports BPF filters, but can only view data by process, without connections or remote address perspective. sniffer combines the advantages of those two projects also adhering a new Plot mode.

***Connections and Process Matching***

On Linux, sniffer refers to the ways in which the [ss](https://man7.org/linux/man-pages/man8/ss.8.html) tool used, obtaining the connections of the `ESTABLISHED` state by [netlink socket](https://man7.org/linux/man-pages/man7/netlink.7.html). Since that approach is more efficient than reading the `/proc/net/*` files directly. But both need to aggregate and calculate the network traffic of the process by matching the `inode` information under `/proc/${pid}/fd`.

On macOS, the [lsof](https://ss64.com/osx/lsof.html) command is invoked, which relies on capturing the command output for analyzing process connections information. And sniffer uses the API provided by [gopsutil](https://github.com/shirou/gopsutil) directly on Windows.

## Installation

***sniffer*** manipulates the `libpcap` library to capture user-level packets hence you need to have it installed first.

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

after that, install sniffer

```shell
go get github.com/chenjiandongx/sinffer
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
  -p, --pids ints                    pids to watch in processes mode (default all processes)
  -u, --unit string                  unit of traffic stats in processes mode, optional: B, KB, MB, GB (default "KB")
  -v, --version                      version for sniffer
```

## View Mode

***Bytes Mode:*** display traffic stats in bytes by the Table widget.

![](https://user-images.githubusercontent.com/19553554/141689557-75e9959f-62db-45d8-85e2-1d8f9e8a0cfb.jpg)

***Packets Mode:*** display traffic stats in packets by the Table widget.

![](https://user-images.githubusercontent.com/19553554/141689559-ee93b3f2-9fc2-424a-aa42-78ae9bc94e12.jpg)

***Processes Mode:*** display traffic stats groups by process using Plot widget.

![](https://user-images.githubusercontent.com/19553554/141689569-eca76a82-219b-4e21-8d06-bbddea7bad40.jpg)

## License

MIT [©chenjiandongx](https://github.com/chenjiandongx)
