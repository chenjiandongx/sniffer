//go:build linux
// +build linux

package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tcpEstablished = uint8(0x01)
	udpConnection  = uint8(0x07)

	sizeOfInetDiagRequest = 72
	sockDiagByFamily      = 20
)

var nativeEndian binary.ByteOrder

// getNativeEndian gets native endianness for the system
func getNativeEndian() binary.ByteOrder {
	if nativeEndian == nil {
		var x uint32 = 0x01020304
		if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
			nativeEndian = binary.BigEndian
		} else {
			nativeEndian = binary.LittleEndian
		}
	}
	return nativeEndian
}

type be16 [2]byte

// Int be16 to int
func (v be16) Int() int {
	v2 := *(*uint16)(unsafe.Pointer(&v))
	return int(v.Swap(v2))
}

// Swap swaps a 16 bit value if we aren't big endian
func (v be16) Swap(i uint16) uint16 {
	if getNativeEndian() == binary.BigEndian {
		return i
	}
	return (i&0xff00)>>8 | (i&0xff)<<8
}

// PortHex parses be16 to hex
func (v be16) PortHex() string {
	return hex.EncodeToString(v[0:])
}

type be32 [4]byte

// inetDiagSockID sock_diag
/* inet_diag.h
struct inet_diag_sockid {
	__be16  idiag_sport;
	__be16  idiag_dport;
	__be32  idiag_src[4];
	__be32  idiag_dst[4];
	__u32   idiag_if;
	__u32   idiag_cookie[2];
#define INET_DIAG_NOCOOKIE (~0U)
};
*/
type inetDiagSockID struct {
	IdiagSport  be16
	IdiagDport  be16
	IdiagSrc    [4]be32
	IdiagDst    [4]be32
	IdiagIF     uint32
	IdiagCookie [2]uint32
}

// inetDiagReqV2 sock_diag
/* inet_diag.h
struct inet_diag_req_v2 {
        __u8    sdiag_family;
        __u8    sdiag_protocol;
        __u8    idiag_ext;
        __u8    pad;
        __u32   idiag_states;
        struct inet_diag_sockid id;
};
*/
type inetDiagReqV2 struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	ID       inetDiagSockID
}

// inetDiagMsg receiv msg
/* inet_diag.h
Base info structure. It contains Socket identity (addrs/ports/cookie) and, alas, the information shown by netstat.
struct inet_diag_msg {
        __u8    idiag_family;
        __u8    idiag_state;
        __u8    idiag_timer;
        __u8    idiag_retrans;

        struct inet_diag_sockid id;

        __u32   idiag_expires;
        __u32   idiag_rqueue;
        __u32   idiag_wqueue;
        __u32   idiag_uid;
        __u32   idiag_inode;
};
*/
type inetDiagMsg struct {
	IDiagFamily  uint8
	IDiagState   uint8
	IDiagTimer   uint8
	IDiagRetrans uint8
	ID           inetDiagSockID
	IDiagExpires uint32
	IDiagRqueue  uint32
	IDiagWqueue  uint32
	IDiagUid     uint32
	IDiagInode   uint32
}

// inetDiagRequest diag_request
/* go/src/syscall/ztypes_linux_amd64.go
type NlMsghdr struct {
        Len   uint32
        Type  uint16
        Flags uint16
        Seq   uint32
        Pid   uint32
}
*/
type inetDiagRequest struct {
	Nlh     syscall.NlMsghdr
	ReqDiag inetDiagReqV2
}

type netlinkConn struct{}

// ipv4 be32 to string
func (nl *netlinkConn) ipv4(b be32) string {
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

// ipv6 be32 to string
func (nl *netlinkConn) ipv6(b [4]be32) string {
	ip := make(net.IP, net.IPv6len)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			ip[4*i+j] = b[i][j]
		}
	}
	return ip.String()
}

// ipHex2String ip hex to string
func (nl *netlinkConn) ipHex2String(family uint8, ip [4]be32) (string, error) {
	switch family {
	case unix.AF_INET:
		return nl.ipv4(ip[0]), nil
	case unix.AF_INET6:
		return nl.ipv6(ip), nil
	default:
		return "", errors.New("family is not unix.AF_INET or unix.AF_INET6")
	}
}

// sockdiagSend sends netlinkConn msgs
// see https://github.com/sivasankariit/iproute2/blob/1179ab033c31d2c67f406be5bcd5e4c0685855fe/misc/ss.c#L1575-L1640
func (nl *netlinkConn) sockdiagSend(proto, family uint8, states uint32) (skfd int, err error) {
	if skfd, err = unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_SOCK_DIAG); err != nil {
		return -1, err
	}

	var diagReq inetDiagRequest
	diagReq.Nlh.Type = sockDiagByFamily

	// man 7 netlinkConn: NLM_F_DUMP Convenience macro; equivalent to (NLM_F_ROOT|NLM_F_MATCH).
	diagReq.Nlh.Flags = unix.NLM_F_DUMP | unix.NLM_F_REQUEST
	diagReq.ReqDiag.Family = family
	diagReq.ReqDiag.Protocol = proto
	diagReq.ReqDiag.States = states
	diagReq.Nlh.Len = uint32(unsafe.Sizeof(diagReq))

	buffer := make([]byte, sizeOfInetDiagRequest)
	*(*inetDiagRequest)(unsafe.Pointer(&buffer[0])) = diagReq

	sockAddrNl := unix.SockaddrNetlink{Family: syscall.AF_NETLINK}
	timeout := syscall.NsecToTimeval((200 * time.Millisecond).Nanoseconds())
	if err = syscall.SetsockoptTimeval(skfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return 0, err
	}

	if err = unix.Sendmsg(skfd, buffer, nil, &sockAddrNl, 0); err != nil {
		return -1, err
	}
	return skfd, nil
}

func (nl *netlinkConn) sockdiagRecv(skfd, proto int, inodeMap map[uint32]string) (map[LocalSocket]string, error) {
	sockets := make(map[LocalSocket]string)
	buffer := make([]byte, os.Getpagesize())
loop:
	for {
		n, _, _, _, err := unix.Recvmsg(skfd, buffer, nil, 0)
		if err != nil {
			return sockets, err
		}

		if n == 0 {
			break loop
		}

		msgs, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return sockets, err
		}

		for _, msg := range msgs {
			if msg.Header.Type == syscall.NLMSG_DONE {
				break loop
			}

			m := (*inetDiagMsg)(unsafe.Pointer(&msg.Data[0]))
			srcIP, _ := nl.ipHex2String(m.IDiagFamily, m.ID.IdiagSrc)

			var p Protocol
			switch proto {
			case syscall.IPPROTO_TCP:
				p = ProtoTCP
			case syscall.IPPROTO_UDP:
				p = ProtoUDP
			}
			sockets[LocalSocket{IP: srcIP, Port: uint16(m.ID.IdiagSport.Int()), Protocol: p}] = inodeMap[m.IDiagInode]
		}
	}

	return sockets, nil
}

func (nl *netlinkConn) getOpenSockets(inodeMap map[uint32]string) (map[LocalSocket]string, error) {
	sockets := make(map[LocalSocket]string)

	type Req struct {
		Protocol int
		Family   uint8
		State    uint32
	}

	reqs := []Req{
		{syscall.IPPROTO_TCP, syscall.AF_INET, uint32(1 | 1<<tcpEstablished)},
		{syscall.IPPROTO_TCP, syscall.AF_INET6, uint32(1 | 1<<tcpEstablished)},
		{syscall.IPPROTO_UDP, syscall.AF_INET, uint32(1 << udpConnection)},
		{syscall.IPPROTO_UDP, syscall.AF_INET6, uint32(1 << udpConnection)},
	}

	type Fd struct {
		fd, proto int
	}
	var fds []Fd
	for _, req := range reqs {
		fd, err := nl.sockdiagSend(uint8(req.Protocol), req.Family, req.State)
		if err != nil {
			return nil, err
		}

		defer syscall.Close(fd)
		fds = append(fds, Fd{fd, req.Protocol})
	}

	for _, fd := range fds {
		m, err := nl.sockdiagRecv(fd.fd, fd.proto, inodeMap)
		if err != nil {
			return sockets, err
		}

		for k, v := range m {
			sockets[k] = v
		}
	}

	return sockets, nil
}

func (nl *netlinkConn) getAllProcsInodes(pids []int32) map[uint32]string {
	inode2Procs := make(map[uint32]string)
	for _, pid := range pids {
		procName, inodes, err := nl.getProcInodes(pid)
		if err != nil {
			continue
		}

		for _, inode := range inodes {
			inode2Procs[inode] = procName
		}
	}
	return inode2Procs
}

func (nl *netlinkConn) getProcInodes(pid int32) (string, []uint32, error) {
	var inodeFds []uint32
	procName, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return procName, inodeFds, err
	}

	f, err := os.Open(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return procName, inodeFds, err
	}
	defer f.Close()

	files, err := f.Readdir(0)
	if err != nil {
		return procName, inodeFds, err
	}

	for _, file := range files {
		inode, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, file.Name()))
		if err != nil {
			continue
		}
		// Socket:[1070205860]
		if !strings.HasPrefix(inode, "socket:[") {
			continue
		}

		inodeInt, err := strconv.Atoi(inode[8 : len(inode)-1])
		if err != nil {
			continue
		}
		inodeFds = append(inodeFds, uint32(inodeInt))
	}
	return filepath.Base(procName), inodeFds, nil
}

func (nl *netlinkConn) listPids() ([]int32, error) {
	var pids []int32
	d, err := os.Open("/proc")
	if err != nil {
		return pids, err
	}
	defer d.Close()

	fnames, err := d.Readdirnames(-1)
	if err != nil {
		return pids, err
	}

	for _, fname := range fnames {
		pid, err := strconv.ParseInt(fname, 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, int32(pid))
	}

	return pids, nil
}

func (nl *netlinkConn) GetOpenSockets() (OpenSockets, error) {
	pids, err := nl.listPids()
	if err != nil {
		return nil, err
	}

	inodeMap := nl.getAllProcsInodes(pids)
	return nl.getOpenSockets(inodeMap)
}

func (nl *netlinkConn) GetProcSockets(pid int32) (OpenSockets, error) {
	return nil, nil
}

func GetSocketFetcher() SocketFetcher {
	return &netlinkConn{}
}
