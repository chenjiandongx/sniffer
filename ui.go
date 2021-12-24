package main

import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	"github.com/chenjiandongx/termui/v3"
	"github.com/chenjiandongx/termui/v3/widgets"
	"github.com/dustin/go-humanize"
	"github.com/gammazero/deque"
)

const (
	maxRows    = 64
	timeFormat = "15:04:05"
	padding    = 6
)

type UIComponent struct {
	viewer Viewer
}

type ViewMode uint8

func (vm ViewMode) Validate() error {
	switch vm {
	case ModeTableBytes, ModeTablePackets, ModePlotProcesses:
		return nil
	}
	return fmt.Errorf("invalid view mode %d", vm)
}

const (
	ModeTableBytes ViewMode = iota
	ModeTablePackets
	ModePlotProcesses
)

type Unit string

const (
	UnitB  Unit = "B"
	UnitKB Unit = "KB"
	UnitKb Unit = "Kb"
	UnitMB Unit = "MB"
	UnitMb Unit = "Mb"
	UnitGB Unit = "GB"
	UnitGb Unit = "Gb"
)

func (u Unit) Validate() error {
	switch u {
	case UnitB, UnitKB, UnitKb, UnitMB, UnitMb, UnitGB, UnitGb:
		return nil
	}
	return fmt.Errorf("invalid unit %s", u)
}

func (u Unit) String() string {
	return string(u)
}

func (u Unit) Ratio() float64 {
	var ratio float64 = 1
	switch u {
	case UnitB:
		ratio = 1
	case UnitKB:
		ratio = 1024
	case UnitKb:
		ratio = 1024 / 8
	case UnitMB:
		ratio = 1024 * 1024
	case UnitMb:
		ratio = 1024 * 1024 / 8
	case UnitGB:
		ratio = 1024 * 1024 * 1024
	case UnitGb:
		ratio = 1024 * 1024 * 1024 / 8
	}
	return ratio
}

func newFooter() *widgets.Paragraph {
	return newParagraph("<space> Pause. <q> Exit. <s> Switch mode. <tab> Rearrange tables")
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
	table.Title = title
	table.RowSeparator = false
	table.TextAlignment = termui.AlignLeft
	table.TextStyle = termui.NewStyle(termui.ColorClear)
	table.BorderStyle = termui.NewStyle(termui.ColorClear)
	table.VerticalLine = ' '
	table.RowStyles = map[int]termui.Style{0: termui.NewStyle(termui.ColorCyan)}
	return table
}

func newPlot(title string, num int) *widgets.Plot {
	plot := widgets.NewPlot()
	plot.Title = title
	plot.TitleStyle = termui.NewStyle(termui.ColorWhite)
	plot.BorderStyle = termui.NewStyle(termui.ColorClear)
	plot.Data = make([][]float64, num)
	plot.LineColors = []termui.Color{termui.ColorBlue, termui.ColorGreen}
	plot.AxesColor = termui.ColorClear
	plot.DisableXAxisLabel = true
	return plot
}

func NewUIComponent(opt Options) *UIComponent {
	ui := &UIComponent{}
	switch opt.ViewMode {
	case ModeTableBytes, ModeTablePackets:
		ui.viewer = &TableViewer{
			footer:      newFooter(),
			processes:   newTable("Process Name"),
			remoteAddrs: newTable("Remote Address"),
			connections: newTable("Connections"),
			mode:        opt.ViewMode,
			unit:        opt.Unit,
		}
	default:
		ui.viewer = &PlotViewer{
			footer:      newFooter(),
			packetsPlot: newPlot("Packets: Blue Up / Green Down", 2),
			bytesPlot:   newPlot(fmt.Sprintf("Bytes: <Unit %sps> Blue Up / Green Down", opt.Unit.String()), 2),
			connsPlot:   newPlot("Connections", 1),
			pids:        opt.Pids,
			unit:        opt.Unit,
		}
	}

	if err := termui.Init(); err != nil {
		exit(err.Error())
	}
	ui.viewer.Setup()
	return ui
}

func (ui *UIComponent) Close() {
	termui.Close()
}

type queue struct {
	size  int
	deque *deque.Deque
}

func (q *queue) Put(v float64) {
	if q.deque.Len() >= q.size {
		q.deque.PopFront()
	}
	q.deque.PushBack(v)
}

func (q *queue) Get(ratio float64) []float64 {
	var nums []float64
	l := q.deque.Len()
	for i := 0; i < l; i++ {
		nums = append(nums, q.deque.At(i).(float64)/ratio)
	}
	return nums
}

func (q *queue) Resize(size int) {
	for q.deque.Len() >= size {
		q.deque.PopFront()
	}
	q.size = size
}

type Viewer interface {
	Setup()
	Shift()
	Resize(width, height int)
	Render(stats interface{})
}

type PlotViewer struct {
	header *widgets.Paragraph
	footer *widgets.Paragraph

	packetsPlot     *widgets.Plot
	packetsUpList   *queue
	packetsDownList *queue
	bytesPlot       *widgets.Plot
	bytesUpList     *queue
	bytesDownList   *queue
	connsPlot       *widgets.Plot
	connsList       *queue
	plotRef         []*widgets.Plot

	dataRef  [][]*queue
	grid     *termui.Grid
	shiftIdx int
	count    int
	unit     Unit
	pids     []int32
}

func (pv *PlotViewer) Setup() {
	pv.header = newParagraph(pv.getHeaderText())
	pv.plotRef = []*widgets.Plot{pv.bytesPlot, pv.packetsPlot, pv.connsPlot}
	width, height := termui.TerminalDimensions()

	pv.bytesUpList = pv.newQueue(width/2 - padding)
	pv.bytesDownList = pv.newQueue(width/2 - padding)
	pv.packetsUpList = pv.newQueue(width/2 - padding)
	pv.packetsDownList = pv.newQueue(width/2 - padding)
	pv.connsList = pv.newQueue(width/2 - padding)
	pv.shiftIdx = -1

	pv.dataRef = [][]*queue{{pv.bytesUpList, pv.bytesDownList}, {pv.packetsUpList, pv.packetsDownList}, {pv.connsList}}
	pv.grid = pv.newGrid(width, height)
}

func (pv *PlotViewer) newQueue(size int) *queue {
	return &queue{size: size, deque: deque.New()}
}

func (pv *PlotViewer) getHeaderText() string {
	now := time.Now().Format(timeFormat)
	if len(pv.pids) <= 0 {
		return fmt.Sprintf("[Processes Mode] Now: %s  Pids All", now)
	}
	buf := &bytes.Buffer{}
	for i, pid := range pv.pids {
		buf.WriteString(strconv.Itoa(int(pid)))
		if i+1 != len(pv.pids) {
			buf.WriteString(" ")
		}
	}
	return fmt.Sprintf("[Processes Mode] Now: %s  Pids </ %s />", now, buf.String())
}

func (pv *PlotViewer) updatePackets(data *NetworkData) {
	pv.packetsUpList.Put(float64(data.UploadPackets))
	pv.packetsDownList.Put(float64(data.DownloadPackets))
	pv.packetsPlot.Data[0] = pv.packetsUpList.Get(1)
	pv.packetsPlot.Data[1] = pv.packetsDownList.Get(1)
}

func (pv *PlotViewer) updateBytes(data *NetworkData) {
	pv.bytesUpList.Put(float64(data.UploadBytes))
	pv.bytesDownList.Put(float64(data.DownloadBytes))
	pv.bytesPlot.Data[0] = pv.bytesUpList.Get(pv.unit.Ratio())
	pv.bytesPlot.Data[1] = pv.bytesDownList.Get(pv.unit.Ratio())
}

func (pv *PlotViewer) updateConnections(data *NetworkData) {
	pv.connsList.Put(float64(data.ConnCount))
	pv.connsPlot.Data[0] = pv.connsList.Get(1)
}

func (pv *PlotViewer) newGrid(width, height int) *termui.Grid {
	grid := termui.NewGrid()
	grid.SetRect(0, 0, width, height)

	num := len(pv.plotRef)
	for _, lst := range pv.dataRef[(pv.shiftIdx+1)%num] {
		lst.Resize(width/2 - padding)
	}
	for _, lst := range pv.dataRef[(pv.shiftIdx+2)%num] {
		lst.Resize(width/2 - padding)
	}
	for _, lst := range pv.dataRef[(pv.shiftIdx+3)%num] {
		lst.Resize(width - padding)
	}

	grid.Set(
		termui.NewRow(0.03, termui.NewCol(1.0, pv.header)),
		termui.NewRow(0.47,
			termui.NewCol(1.0/2, pv.plotRef[(pv.shiftIdx+1)%num]),
			termui.NewCol(1.0/2, pv.plotRef[(pv.shiftIdx+2)%num]),
		),
		termui.NewRow(0.47, termui.NewCol(1.0, pv.plotRef[(pv.shiftIdx+3)%num])),
		termui.NewRow(0.03, termui.NewCol(1.0, pv.footer)),
	)
	return grid
}

func (pv *PlotViewer) Shift() {
	pv.shiftIdx++
	width, height := termui.TerminalDimensions()
	pv.grid = pv.newGrid(width, height)
	pv.render()
}

func (pv *PlotViewer) Resize(width, height int) {
	pv.grid = pv.newGrid(width, height)
	pv.render()
}

func (pv *PlotViewer) Render(stats interface{}) {
	if stats == nil {
		return
	}

	pv.header.Text = pv.getHeaderText()
	pv.count++
	data := stats.(*NetworkData)

	pv.updatePackets(data)
	pv.updateBytes(data)
	pv.updateConnections(data)
	pv.render()
}

func (pv *PlotViewer) render() {
	if pv.count <= 1 {
		return
	}
	termui.Render(pv.grid)
}

type TableViewer struct {
	header      *widgets.Paragraph
	footer      *widgets.Paragraph
	processes   *widgets.Table
	remoteAddrs *widgets.Table
	connections *widgets.Table
	tableRef    []*widgets.Table
	grid        *termui.Grid
	shiftIdx    int
	mode        ViewMode
	unit        Unit
}

func (tv *TableViewer) Setup() {
	tv.header = newParagraph(tv.getHeaderText(0, "", ""))
	tv.tableRef = []*widgets.Table{tv.processes, tv.remoteAddrs, tv.connections}
	width, height := termui.TerminalDimensions()
	tv.grid = tv.newGrid(width, height)
}

func (tv *TableViewer) getHeaderText(conn int, up, down string) string {
	now := time.Now().Format(timeFormat)
	var text string
	switch tv.mode {
	case ModeTableBytes:
		text = fmt.Sprintf("[Bytes Mode] Time: %s  [Total] Conn:%d Up:%s Down:%s", now, conn, up, down)
	case ModeTablePackets:
		text = fmt.Sprintf("[Packets Mode] Time: %s  [Total] Conn:%d Up:%s Down:%s", now, conn, up, down)
	}
	return text
}

func (tv *TableViewer) humanizeNum(n int) string {
	var s string
	switch tv.mode {
	case ModeTableBytes:
		s = fmt.Sprintf("%.1f%s", float64(n)/tv.unit.Ratio(), tv.unit.String())
	case ModeTablePackets:
		s = humanize.Comma(int64(n))
	}
	return s + "ps"
}

func (tv *TableViewer) updateHeader(snapshot *Snapshot) {
	var up, down string
	switch tv.mode {
	case ModeTableBytes:
		up = tv.humanizeNum(snapshot.TotalUploadBytes)
		down = tv.humanizeNum(snapshot.TotalDownloadBytes)
	case ModeTablePackets:
		up = tv.humanizeNum(snapshot.TotalUploadPackets)
		down = tv.humanizeNum(snapshot.TotalDownloadPackets)
	}
	tv.header.Text = tv.getHeaderText(snapshot.TotalConnections, up, down)
}

func (tv *TableViewer) updateProcesses(snapshot *Snapshot) {
	rows := make([][]string, 0)
	for _, r := range snapshot.TopNProcesses(maxRows, tv.mode) {
		var up, down string
		switch tv.mode {
		case ModeTableBytes:
			up = tv.humanizeNum(r.Data.UploadBytes)
			down = tv.humanizeNum(r.Data.DownloadBytes)
		case ModeTablePackets:
			up = tv.humanizeNum(r.Data.UploadPackets)
			down = tv.humanizeNum(r.Data.DownloadPackets)
		}
		rows = append(rows, []string{r.ProcessName, strconv.Itoa(r.Data.ConnCount), up + " / " + down})
	}

	header := []string{"<Pid>:Process", "Connections", "Up / Down"}
	tv.processes.Rows = [][]string{header, make([]string, 3)}
	tv.processes.Rows = append(tv.processes.Rows, rows...)
}

func (tv *TableViewer) updateRemoteAddrs(snapshot *Snapshot) {
	rows := make([][]string, 0)
	for _, r := range snapshot.TopNRemoteAddrs(maxRows, tv.mode) {
		var up, down string
		switch tv.mode {
		case ModeTableBytes:
			up = tv.humanizeNum(r.Data.UploadBytes)
			down = tv.humanizeNum(r.Data.DownloadBytes)
		case ModeTablePackets:
			up = tv.humanizeNum(r.Data.UploadPackets)
			down = tv.humanizeNum(r.Data.DownloadPackets)
		}
		rows = append(rows, []string{r.Addr, strconv.Itoa(r.Data.ConnCount), up + " / " + down})
	}

	header := []string{"Remote Address", "Connections", "Up / Down"}
	tv.remoteAddrs.Rows = [][]string{header, make([]string, 3)}
	tv.remoteAddrs.Rows = append(tv.remoteAddrs.Rows, rows...)
}

func (tv *TableViewer) updateConnections(snapshot *Snapshot) {
	rows := make([][]string, 0)
	for _, r := range snapshot.TopNConnections(maxRows, tv.mode) {
		var up, down string
		switch tv.mode {
		case ModeTableBytes:
			up = tv.humanizeNum(r.Data.UploadBytes)
			down = tv.humanizeNum(r.Data.DownloadBytes)
		case ModeTablePackets:
			up = tv.humanizeNum(r.Data.UploadPackets)
			down = tv.humanizeNum(r.Data.DownloadPackets)
		}

		conn := fmt.Sprintf("<%s>:%d => %s:%d (%s)",
			r.Data.InterfaceName,
			r.Conn.Local.Port,
			r.Conn.Remote.IP,
			r.Conn.Remote.Port,
			r.Conn.Local.Protocol,
		)
		rows = append(rows, []string{conn, r.Data.ProcessName, up + " / " + down})
	}

	header := []string{"Connections", "<Pid>:Process", "Up / Down"}
	tv.connections.Rows = [][]string{header, make([]string, 3)}
	tv.connections.Rows = append(tv.connections.Rows, rows...)
}

func (tv *TableViewer) newGrid(width, height int) *termui.Grid {
	grid := termui.NewGrid()
	grid.SetRect(0, 0, width, height)

	num := len(tv.tableRef)
	w := (width) / 12
	tv.tableRef[(tv.shiftIdx+1)%num].ColumnWidths = []int{w * 2, w * 2, (w * 2) - 1}
	tv.tableRef[(tv.shiftIdx+2)%num].ColumnWidths = []int{w * 2, w * 2, (w * 2) - 1}
	tv.tableRef[(tv.shiftIdx+3)%num].ColumnWidths = []int{w * 6, w * 3, (w * 3) - 1}

	grid.Set(
		termui.NewRow(0.03, termui.NewCol(1.0, tv.header)),
		termui.NewRow(0.47,
			termui.NewCol(1.0/2, tv.tableRef[(tv.shiftIdx+1)%num]),
			termui.NewCol(1.0/2, tv.tableRef[(tv.shiftIdx+2)%num]),
		),
		termui.NewRow(0.47, termui.NewCol(1.0, tv.tableRef[(tv.shiftIdx+3)%num])),
		termui.NewRow(0.03, termui.NewCol(1.0, tv.footer)),
	)
	return grid
}

func (tv *TableViewer) Shift() {
	tv.shiftIdx++
	width, height := termui.TerminalDimensions()
	tv.grid = tv.newGrid(width, height)
	termui.Render(tv.grid)
}

func (tv *TableViewer) Resize(width, height int) {
	tv.grid = tv.newGrid(width, height)
	termui.Render(tv.grid)
}

func (tv *TableViewer) Render(stats interface{}) {
	snapshot := stats.(*Snapshot)
	if snapshot == nil {
		return
	}
	tv.updateHeader(snapshot)
	tv.updateProcesses(snapshot)
	tv.updateRemoteAddrs(snapshot)
	tv.updateConnections(snapshot)
	termui.Render(tv.grid)
}
