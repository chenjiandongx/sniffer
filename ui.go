package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

const (
	maxRows = 64
)

type UIComponent struct {
	header      *widgets.Paragraph
	footer      *widgets.Paragraph
	processes   *widgets.Table
	remoteAddrs *widgets.Table
	connections *widgets.Table
	tableRef    []*widgets.Table
	grid        *termui.Grid
	shiftIdx    int
	mode        RenderMode
	lookup      func(string) string
}

type RenderMode uint8

const (
	RModeBytes RenderMode = iota
	RModePackets
)

func NewUIComponent(lookup func(string) string, mode RenderMode) *UIComponent {
	ui := &UIComponent{
		header:      newHeader(mode),
		footer:      newFooter(),
		processes:   newTable("Process Name"),
		remoteAddrs: newTable("Process Name"),
		connections: newTable("Connections"),
		mode:        mode,
		lookup:      lookup,
	}

	ui.tableRef = []*widgets.Table{ui.processes, ui.remoteAddrs, ui.connections}
	if err := termui.Init(); err != nil {
		panic(err)
	}

	width, height := termui.TerminalDimensions()
	ui.grid = newGrid(ui.shiftIdx, width, height, ui.header, ui.footer, ui.tableRef)
	return ui
}

func newGrid(shift, width, height int, header, footer *widgets.Paragraph, tables []*widgets.Table) *termui.Grid {
	grid := termui.NewGrid()
	grid.SetRect(0, 0, width, height)

	num := len(tables)
	w := (width) / 12
	tables[(shift+1)%num].ColumnWidths = []int{w * 2, w * 2, (w * 2) - 1}
	tables[(shift+2)%num].ColumnWidths = []int{w * 2, w * 2, (w * 2) - 1}
	tables[(shift+3)%num].ColumnWidths = []int{w * 6, w * 3, (w * 3) - 1}

	grid.Set(
		termui.NewRow(0.03, termui.NewCol(1.0, header)),
		termui.NewRow(0.47,
			termui.NewCol(1.0/2, tables[(shift+1)%num]), termui.NewCol(1.0/2, tables[(shift+2)%num]),
		),
		termui.NewRow(0.47, termui.NewCol(1.0, tables[(shift+3)%num])),
		termui.NewRow(0.03, termui.NewCol(1.0, footer)),
	)

	return grid
}

func newHeader(mode RenderMode) *widgets.Paragraph {
	var msg string
	switch mode {
	case RModeBytes:
		msg = "Bytes/s"
	case RModePackets:
		msg = "Packets/s"
	}

	text := fmt.Sprintf("Now: %s  Total Up / Down <%s>: 0ps / 0ps", time.Now().Format("15:04:05"), msg)
	return newParagraph(text)
}

func newFooter() *widgets.Paragraph {
	text := "Press <Space> to pause. Use <Tab> to rearrange tables"
	return newParagraph(text)
}

func newParagraph(text string) *widgets.Paragraph {
	paragraph := widgets.NewParagraph()
	paragraph.Text = text
	paragraph.Border = false
	paragraph.TextStyle = termui.NewStyle(termui.ColorClear)
	paragraph.TextStyle.Modifier = termui.ModifierBold

	return paragraph
}

func newTable(title string) *widgets.Table {
	table := widgets.NewTable()
	table.Title = fmt.Sprintf("Utilization <%s>", title)
	table.RowSeparator = false
	table.TextAlignment = termui.AlignLeft
	table.TextStyle = termui.NewStyle(termui.ColorClear)
	table.BorderStyle = termui.NewStyle(termui.ColorClear)
	table.RowStyles = map[int]termui.Style{0: termui.NewStyle(termui.ColorCyan)}
	return table
}

func (ui *UIComponent) humanizeNumber(n int) string {
	var s string
	switch ui.mode {
	case RModeBytes:
		s = strings.ReplaceAll(humanize.IBytes(uint64(n)), " ", "") + "ps"
	case RModePackets:
		s = humanize.Comma(int64(n)) + "ps"
	}
	return s
}

func (ui *UIComponent) emptyRow(column int) []string {
	return make([]string, column)
}

func (ui *UIComponent) updateHeader(snapshot *Snapshot) {
	now := time.Now().Format("15:04:05")
	var up, down, msg string
	switch ui.mode {
	case RModeBytes:
		up = ui.humanizeNumber(snapshot.TotalUploadBytes)
		down = ui.humanizeNumber(snapshot.TotalDownloadBytes)
		msg = "Bytes/s"
	case RModePackets:
		up = ui.humanizeNumber(snapshot.TotalUploadPackets)
		down = ui.humanizeNumber(snapshot.TotalDownloadPackets)
		msg = "Packets/s"
	}
	ui.header.Text = fmt.Sprintf("Now: %s  Total Up / Down <%s>: %s / %s", now, msg, up, down)
}

func (ui *UIComponent) updateProcesses(snapshot *Snapshot) {
	rows := make([][]string, 0)
	for _, r := range snapshot.TopNProcesses(maxRows, ui.mode) {
		var up, down string
		switch ui.mode {
		case RModeBytes:
			up = ui.humanizeNumber(r.Data.UploadBytes)
			down = ui.humanizeNumber(r.Data.DownloadBytes)
		case RModePackets:
			up = ui.humanizeNumber(r.Data.UploadPackets)
			down = ui.humanizeNumber(r.Data.DownloadPackets)
		}
		rows = append(rows, []string{r.ProcessName, strconv.Itoa(r.Data.ConnCount), up + " / " + down})
	}

	header := []string{"Process", "Connections", "Up / Down"}
	ui.processes.Rows = [][]string{header, ui.emptyRow(3)}
	ui.processes.Rows = append(ui.processes.Rows, rows...)
}

func (ui *UIComponent) updateRemoteAddrs(snapshot *Snapshot) {
	rows := make([][]string, 0)
	for _, r := range snapshot.TopNRemoteAddrs(maxRows, ui.mode) {
		var up, down string
		switch ui.mode {
		case RModeBytes:
			up = ui.humanizeNumber(r.Data.UploadBytes)
			down = ui.humanizeNumber(r.Data.DownloadBytes)
		case RModePackets:
			up = ui.humanizeNumber(r.Data.UploadPackets)
			down = ui.humanizeNumber(r.Data.DownloadPackets)
		}

		// only resolve the TCP IPs
		addr := r.Addr
		if r.Data.Protocol == ProtoTCP {
			addr = ui.lookup(r.Addr)
		}
		rows = append(rows, []string{addr, strconv.Itoa(r.Data.ConnCount), up + " / " + down})
	}

	header := []string{"Remote Address", "Connections", "Up / Down"}
	ui.remoteAddrs.Rows = [][]string{header, ui.emptyRow(3)}
	ui.remoteAddrs.Rows = append(ui.remoteAddrs.Rows, rows...)
}

func (ui *UIComponent) updateConnections(snapshot *Snapshot) {
	rows := make([][]string, 0)
	for _, r := range snapshot.TopNConnections(maxRows, ui.mode) {
		var up, down string
		switch ui.mode {
		case RModeBytes:
			up = ui.humanizeNumber(r.Data.UploadBytes)
			down = ui.humanizeNumber(r.Data.DownloadBytes)
		case RModePackets:
			up = ui.humanizeNumber(r.Data.UploadPackets)
			down = ui.humanizeNumber(r.Data.DownloadPackets)
		}

		// only resolve the TCP IPs
		remoteIP := r.Conn.Remote.IP
		if r.Conn.Local.Protocol == ProtoTCP {
			remoteIP = ui.lookup(r.Conn.Remote.IP)
		}

		conn := fmt.Sprintf("<%s>:%d => %s:%d (%s)",
			r.Data.InterfaceName,
			r.Conn.Local.Port,
			remoteIP,
			r.Conn.Remote.Port,
			r.Conn.Local.Protocol,
		)

		rows = append(rows, []string{conn, r.Data.ProcessName, up + " / " + down})
	}

	header := []string{"Connections", "Process", "Up / Down"}
	ui.connections.Rows = [][]string{header, ui.emptyRow(3)}
	ui.connections.Rows = append(ui.connections.Rows, rows...)
}

func (ui *UIComponent) Shift() {
	ui.shiftIdx++
	width, height := termui.TerminalDimensions()
	ui.grid = newGrid(ui.shiftIdx, width, height, ui.header, ui.footer, ui.tableRef)
	termui.Render(ui.grid)
}

func (ui *UIComponent) Resize(width, height int) {
	ui.grid = newGrid(ui.shiftIdx, width, height, ui.header, ui.footer, ui.tableRef)
	termui.Render(ui.grid)
}

func (ui *UIComponent) Render(snapshot *Snapshot) {
	ui.updateHeader(snapshot)
	ui.updateProcesses(snapshot)
	ui.updateRemoteAddrs(snapshot)
	ui.updateConnections(snapshot)
	termui.Render(ui.grid)
}
