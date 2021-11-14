# sniffer

*A modern alternative network traffic sniffer inspried by [bandwhich](https://github.com/imsnif/bandwhich)(Rust) and [nethogs](https://github.com/raboof/nethogs)(C++) project*

## Introduction

sniffer takes advantage of the [gopacket](https://github.com/google/gopacket) library to sniff geiven network interfaces and records packets info. `gopacket` provides a Golang wrapper for `libpcap` written in C with additional functionality.

sniffer is a useful tool design for troubleshooting network issues since it can distinguish which process or connection causing the vast network traffic by different view modes. It's worth pointing out that sniffer is also responsive to the terminal window size, which makes it adapts all size of terminal automatically.


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
  -d, --devices-prefix stringArray   prefixed devices to monitor (default: any devices)
  -h, --help                         help for sniffer
  -i, --interval int                 interval for refresh rate in seconds (default 1)
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
