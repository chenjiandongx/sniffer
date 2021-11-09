package main

import (
	"sort"
	"sync"

	"github.com/gammazero/deque"
)

const (
	unknownProcessName = "<UNKNOWN>"
)

type Stat struct {
	OpenSockets OpenSockets
	Utilization Utilization
}

type ConnectionData struct {
	DownloadBytes   int
	UploadBytes     int
	UploadPackets   int
	DownloadPackets int
	ProcessName     string
	InterfaceName   string
}

type NetworkData struct {
	UploadBytes     int
	DownloadBytes   int
	UploadPackets   int
	DownloadPackets int
	ConnCount       int
}

func (d *NetworkData) DivideBy(n int) {
	d.UploadBytes /= n
	d.DownloadBytes /= n
	d.UploadPackets /= n
	d.DownloadPackets /= n
}

func (d *ConnectionData) DivideBy(n int) {
	d.UploadBytes /= n
	d.DownloadBytes /= n
	d.UploadPackets /= n
	d.DownloadPackets /= n
}

type ProcessesResult struct {
	ProcessName string
	Data        *NetworkData
}

type RemoteAddrsResult struct {
	Addr string
	Data *NetworkData
}

type ConnectionsResult struct {
	Conn Connection
	Data *ConnectionData
}

type Snapshot struct {
	Processes            map[string]*NetworkData
	RemoteAddrs          map[string]*NetworkData
	Connections          map[Connection]*ConnectionData
	TotalUploadBytes     int
	TotalDownloadBytes   int
	TotalUploadPackets   int
	TotalDownloadPackets int
}

func (s *Snapshot) TopNProcesses(n int, mode RenderMode) []ProcessesResult {
	var items []ProcessesResult
	for k, v := range s.Processes {
		items = append(items, ProcessesResult{ProcessName: k, Data: v})
	}

	switch mode {
	case RModeBytes:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadBytes+items[i].Data.UploadBytes > items[j].Data.DownloadBytes+items[j].Data.UploadBytes
		})
	case RModePackets:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadPackets+items[i].Data.UploadPackets > items[j].Data.DownloadPackets+items[j].Data.UploadPackets
		})
	}

	if len(items) < n {
		n = len(items)
	}
	return items[:n]
}

func (s *Snapshot) TopNRemoteAddrs(n int, mode RenderMode) []RemoteAddrsResult {
	var items []RemoteAddrsResult
	for k, v := range s.RemoteAddrs {
		items = append(items, RemoteAddrsResult{Addr: k, Data: v})
	}

	switch mode {
	case RModeBytes:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadBytes+items[i].Data.UploadBytes > items[j].Data.DownloadBytes+items[j].Data.UploadBytes
		})
	case RModePackets:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadPackets+items[i].Data.UploadPackets > items[j].Data.DownloadPackets+items[j].Data.UploadPackets
		})
	}

	if len(items) < n {
		n = len(items)
	}
	return items[:n]
}

func (s *Snapshot) TopNConnections(n int, mode RenderMode) []ConnectionsResult {
	var items []ConnectionsResult
	for k, v := range s.Connections {
		items = append(items, ConnectionsResult{Conn: k, Data: v})
	}

	switch mode {
	case RModeBytes:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadBytes+items[i].Data.UploadBytes > items[j].Data.DownloadBytes+items[j].Data.UploadBytes
		})
	case RModePackets:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadPackets+items[i].Data.UploadPackets > items[j].Data.DownloadPackets+items[j].Data.UploadPackets
		})
	}

	if len(items) < n {
		n = len(items)
	}
	return items[:n]
}

type StatsManager struct {
	mut   sync.Mutex
	ring  *deque.Deque
	ratio int
}

func NewStatsManager(ratio int) *StatsManager {
	return &StatsManager{
		ring:  deque.New(),
		ratio: ratio,
	}
}

func (s *StatsManager) Put(stat Stat) {
	s.mut.Lock()
	defer s.mut.Unlock()

	const maxsize = 5
	if s.ring.Len() >= maxsize {
		s.ring.PopFront()
	}
	s.ring.PushBack(stat)
}

func (s *StatsManager) getProcName(openSockets OpenSockets, localSocket LocalSocket) string {
	ips := []string{localSocket.IP, "*"}
	for _, ip := range ips {
		cloned := localSocket
		cloned.IP = ip

		v, ok := openSockets[cloned]
		if ok {
			return v
		}
	}
	return unknownProcessName
}

func (s *StatsManager) GetSnapshot() *Snapshot {
	s.mut.Lock()
	defer s.mut.Unlock()

	processes := map[string]*NetworkData{}
	remoteAddr := map[string]*NetworkData{}
	connections := map[Connection]*ConnectionData{}
	visited := map[Connection]bool{}

	var totalUploadBytes, totalDownloadBytes, totalUploadPackets, totalDownloadPackets int

	size := s.ring.Len()
	if size <= 0 {
		return nil
	}

	for i := 0; i < size; i++ {
		stat := s.ring.At(i).(Stat)
		for conn, info := range stat.Utilization {
			procName := s.getProcName(stat.OpenSockets, conn.Local)
			if _, ok := connections[conn]; !ok {
				connections[conn] = &ConnectionData{
					InterfaceName: info.Interface,
					ProcessName:   procName,
				}
			}
			connections[conn].UploadBytes += info.UploadBytes
			connections[conn].DownloadBytes += info.DownloadBytes
			connections[conn].UploadPackets += info.UploadPackets
			connections[conn].DownloadPackets += info.DownloadPackets

			if _, ok := remoteAddr[conn.Remote.IP]; !ok {
				remoteAddr[conn.Remote.IP] = &NetworkData{}
			}
			if !visited[conn] {
				remoteAddr[conn.Remote.IP].ConnCount++
			}
			remoteAddr[conn.Remote.IP].UploadBytes += info.UploadBytes
			remoteAddr[conn.Remote.IP].DownloadBytes += info.UploadBytes
			remoteAddr[conn.Remote.IP].UploadPackets += info.UploadPackets
			remoteAddr[conn.Remote.IP].DownloadPackets += info.DownloadPackets

			if _, ok := processes[procName]; !ok {
				processes[procName] = &NetworkData{}
			}
			processes[procName].UploadBytes += info.UploadBytes
			processes[procName].DownloadBytes += info.DownloadBytes
			processes[procName].UploadPackets += info.UploadPackets
			processes[procName].DownloadPackets += info.DownloadPackets
			if !visited[conn] {
				processes[procName].ConnCount++
			}

			totalUploadPackets += info.UploadPackets
			totalDownloadPackets += info.DownloadPackets
			totalUploadBytes += info.UploadBytes
			totalDownloadBytes += info.DownloadBytes
			visited[conn] = true
		}
	}

	size = size * s.ratio
	for _, v := range processes {
		v.DivideBy(size)
	}
	for _, v := range remoteAddr {
		v.DivideBy(size)
	}
	for _, v := range connections {
		v.DivideBy(size)
	}

	return &Snapshot{
		Processes:            processes,
		RemoteAddrs:          remoteAddr,
		Connections:          connections,
		TotalUploadBytes:     totalUploadBytes / size,
		TotalDownloadBytes:   totalDownloadBytes / size,
		TotalUploadPackets:   totalUploadPackets / size,
		TotalDownloadPackets: totalDownloadPackets / size,
	}
}
