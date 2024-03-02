package main

import (
	"sort"
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
	TotalConnections     int
}

func (s *Snapshot) TopNProcesses(n int, mode ViewMode) []ProcessesResult {
	var items []ProcessesResult
	for k, v := range s.Processes {
		items = append(items, ProcessesResult{ProcessName: k, Data: v})
	}

	switch mode {
	case ModeTableBytes:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadBytes+items[i].Data.UploadBytes > items[j].Data.DownloadBytes+items[j].Data.UploadBytes
		})
	case ModeTablePackets:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadPackets+items[i].Data.UploadPackets > items[j].Data.DownloadPackets+items[j].Data.UploadPackets
		})
	}

	if len(items) < n {
		n = len(items)
	}
	return items[:n]
}

func (s *Snapshot) TopNRemoteAddrs(n int, mode ViewMode) []RemoteAddrsResult {
	var items []RemoteAddrsResult
	for k, v := range s.RemoteAddrs {
		items = append(items, RemoteAddrsResult{Addr: k, Data: v})
	}

	switch mode {
	case ModeTableBytes:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadBytes+items[i].Data.UploadBytes > items[j].Data.DownloadBytes+items[j].Data.UploadBytes
		})
	case ModeTablePackets:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadPackets+items[i].Data.UploadPackets > items[j].Data.DownloadPackets+items[j].Data.UploadPackets
		})
	}

	if len(items) < n {
		n = len(items)
	}
	return items[:n]
}

func (s *Snapshot) TopNConnections(n int, mode ViewMode) []ConnectionsResult {
	var items []ConnectionsResult
	for k, v := range s.Connections {
		items = append(items, ConnectionsResult{Conn: k, Data: v})
	}

	switch mode {
	case ModeTableBytes:
		sort.Slice(items, func(i, j int) bool {
			return items[i].Data.DownloadBytes+items[i].Data.UploadBytes > items[j].Data.DownloadBytes+items[j].Data.UploadBytes
		})
	case ModeTablePackets:
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
	ratio int
	stat  Stat
	mode  ViewMode
}

func NewStatsManager(opt Options) *StatsManager {
	return &StatsManager{
		ratio: opt.Interval,
		mode:  opt.ViewMode,
	}
}

func (s *StatsManager) Put(stat Stat) {
	s.stat = stat
}

func (s *StatsManager) getProcName(openSockets OpenSockets, localSocket LocalSocket) string {
	ips := []string{localSocket.IP, "*"}
	for _, ip := range ips {
		cloned := localSocket
		cloned.IP = ip

		v, ok := openSockets[cloned]
		if ok {
			return v.String()
		}
	}
	return unknownProcessName
}

func (s *StatsManager) GetStats() interface{} {
	if s.mode == ModePlotProcesses {
		return s.getNetworkData()
	}
	return s.getSnapshot()
}

func (s *StatsManager) getNetworkData() *NetworkData {
	visited := map[Connection]bool{}
	var uploadBytes, downloadBytes, uploadPackets, downloadPackets, connections int

	stat := s.stat
	for conn, info := range stat.Utilization {
		procName := s.getProcName(stat.OpenSockets, conn.Local)
		if procName == unknownProcessName {
			continue
		}

		if !visited[conn] {
			connections++
			visited[conn] = true
		}

		uploadBytes += info.UploadBytes
		downloadBytes += info.DownloadBytes
		uploadPackets += info.UploadPackets
		downloadPackets += info.DownloadPackets
	}

	return &NetworkData{
		UploadBytes:     uploadBytes / s.ratio,
		DownloadBytes:   downloadBytes / s.ratio,
		UploadPackets:   uploadPackets / s.ratio,
		DownloadPackets: downloadPackets / s.ratio,
		ConnCount:       connections,
	}
}

func (s *StatsManager) getSnapshot() *Snapshot {
	processes := map[string]*NetworkData{}
	remoteAddr := map[string]*NetworkData{}
	connections := map[Connection]*ConnectionData{}
	visited := map[Connection]bool{}
	var totalUploadBytes, totalDownloadBytes, totalUploadPackets, totalDownloadPackets, totalConnections int

	stat := s.stat
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
			totalConnections++
			remoteAddr[conn.Remote.IP].ConnCount++
		}
		remoteAddr[conn.Remote.IP].UploadBytes += info.UploadBytes
		remoteAddr[conn.Remote.IP].DownloadBytes += info.UploadBytes
		remoteAddr[conn.Remote.IP].UploadPackets += info.UploadPackets
		remoteAddr[conn.Remote.IP].DownloadPackets += info.DownloadPackets

		if _, ok := processes[procName]; !ok {
			processes[procName] = &NetworkData{}
		}
		if !visited[conn] {
			processes[procName].ConnCount++
		}
		processes[procName].UploadBytes += info.UploadBytes
		processes[procName].DownloadBytes += info.DownloadBytes
		processes[procName].UploadPackets += info.UploadPackets
		processes[procName].DownloadPackets += info.DownloadPackets

		totalUploadPackets += info.UploadPackets
		totalDownloadPackets += info.DownloadPackets
		totalUploadBytes += info.UploadBytes
		totalDownloadBytes += info.DownloadBytes
		visited[conn] = true
	}

	for _, v := range processes {
		v.DivideBy(s.ratio)
	}
	for _, v := range remoteAddr {
		v.DivideBy(s.ratio)
	}
	for _, v := range connections {
		v.DivideBy(s.ratio)
	}

	return &Snapshot{
		Processes:            processes,
		RemoteAddrs:          remoteAddr,
		Connections:          connections,
		TotalUploadBytes:     totalUploadBytes / s.ratio,
		TotalDownloadBytes:   totalDownloadBytes / s.ratio,
		TotalUploadPackets:   totalUploadPackets / s.ratio,
		TotalDownloadPackets: totalDownloadPackets / s.ratio,
		TotalConnections:     totalConnections,
	}
}
