//go:build windows

package tray

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lxn/walk"
)

func showDashboard(owner walk.Form, h Handlers) {
	dlg, err := walk.NewDialog(nil)
	if err != nil {
		walk.MsgBox(owner, "Error", "Could not open dashboard: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	_ = dlg.SetTitle("Windows Defender but Good — Dashboard")
	_ = dlg.SetLayout(walk.NewVBoxLayout())
	_ = dlg.SetMinMaxSize(walk.Size{Width: 720, Height: 520}, walk.Size{})

	tabs, err := walk.NewTabWidget(dlg)
	if err != nil {
		dlg.Close(0)
		return
	}

	addSettingsTab(dlg, tabs, h)
	addQuarTab(dlg, tabs, h)
	addHistTab(tabs, h)
	addStatusTab(tabs, h)

	dlg.Run()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func labeledLineEdit(parent walk.Container, labelText string) *walk.LineEdit {
	row, _ := walk.NewComposite(parent)
	_ = row.SetLayout(walk.NewHBoxLayout())
	lbl, _ := walk.NewLabel(row)
	_ = lbl.SetText(labelText)
	_ = lbl.SetMinMaxSize(walk.Size{Width: 180}, walk.Size{Width: 180})
	le, _ := walk.NewLineEdit(row)
	return le
}

func labeledCheckBox(parent walk.Container, labelText string) *walk.CheckBox {
	row, _ := walk.NewComposite(parent)
	_ = row.SetLayout(walk.NewHBoxLayout())
	lbl, _ := walk.NewLabel(row)
	_ = lbl.SetText(labelText)
	_ = lbl.SetMinMaxSize(walk.Size{Width: 180}, walk.Size{Width: 180})
	cb, _ := walk.NewCheckBox(row)
	return cb
}

func rightAlignedBar(parent walk.Container) *walk.Composite {
	bar, _ := walk.NewComposite(parent)
	_ = bar.SetLayout(walk.NewHBoxLayout())
	_, _ = walk.NewHSpacer(bar)
	return bar
}

// ── Settings tab ──────────────────────────────────────────────────────────────

func addSettingsTab(dlg *walk.Dialog, tabs *walk.TabWidget, h Handlers) {
	page, _ := walk.NewTabPage()
	_ = page.SetTitle("Settings")
	vbl := walk.NewVBoxLayout()
	_ = vbl.SetMargins(walk.Margins{HNear: 12, VNear: 12, HFar: 12, VFar: 8})
	_ = page.SetLayout(vbl)

	cfg := h.GetConfig()

	vtKey := labeledLineEdit(page, "VirusTotal API Key")
	vtKey.SetPasswordMode(true)
	_ = vtKey.SetText(cfg.APIKey)

	mbKey := labeledLineEdit(page, "MalwareBazaar Key")
	mbKey.SetPasswordMode(true)
	_ = mbKey.SetText(cfg.MalwareBazaarAPIKey)

	detThresh := labeledLineEdit(page, "Detection threshold")
	_ = detThresh.SetText(strconv.Itoa(cfg.DetectionThreshold))

	heuThresh := labeledLineEdit(page, "Heuristic threshold")
	_ = heuThresh.SetText(strconv.Itoa(cfg.HeuristicThreshold))

	feedRefresh := labeledLineEdit(page, "Feed refresh (hours)")
	_ = feedRefresh.SetText(fmt.Sprintf("%.1f", cfg.HashFeedRefreshHours))

	quarDir := labeledLineEdit(page, "Quarantine dir")
	_ = quarDir.SetText(cfg.QuarantineDir)

	risky := labeledCheckBox(page, "Risky files only")
	risky.SetChecked(cfg.RiskyOnly)

	enableFeed := labeledCheckBox(page, "Enable hash feed")
	enableFeed.SetChecked(cfg.EnableHashFeed)

	// Watched folders — multi-line TextEdit
	fRow, _ := walk.NewComposite(page)
	_ = fRow.SetLayout(walk.NewHBoxLayout())
	fLbl, _ := walk.NewLabel(fRow)
	_ = fLbl.SetText("Watched folders\n(one per line)")
	_ = fLbl.SetMinMaxSize(walk.Size{Width: 180}, walk.Size{Width: 180})
	foldersEdit, _ := walk.NewTextEdit(fRow)
	_ = foldersEdit.SetText(strings.Join(cfg.WatchedFolders, "\r\n"))

	_, _ = walk.NewVSpacer(page)

	bar := rightAlignedBar(page)

	saveBtn, _ := walk.NewPushButton(bar)
	_ = saveBtn.SetText("Save")
	saveBtn.Clicked().Attach(func() {
		newCfg := *cfg
		newCfg.APIKey = strings.TrimSpace(vtKey.Text())
		newCfg.MalwareBazaarAPIKey = strings.TrimSpace(mbKey.Text())
		newCfg.QuarantineDir = strings.TrimSpace(quarDir.Text())
		newCfg.RiskyOnly = risky.Checked()
		newCfg.EnableHashFeed = enableFeed.Checked()

		if v, err := strconv.Atoi(strings.TrimSpace(detThresh.Text())); err == nil {
			newCfg.DetectionThreshold = v
		}
		if v, err := strconv.Atoi(strings.TrimSpace(heuThresh.Text())); err == nil {
			newCfg.HeuristicThreshold = v
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(feedRefresh.Text()), 64); err == nil {
			newCfg.HashFeedRefreshHours = v
		}

		var folders []string
		for _, line := range strings.Split(foldersEdit.Text(), "\n") {
			if f := strings.TrimSpace(strings.TrimRight(line, "\r")); f != "" {
				folders = append(folders, f)
			}
		}
		if len(folders) > 0 {
			newCfg.WatchedFolders = folders
		}

		if err := h.SaveConfig(&newCfg); err != nil {
			walk.MsgBox(dlg, "Error", "Could not save: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
			return
		}
		h.Restart()
	})

	closeBtn, _ := walk.NewPushButton(bar)
	_ = closeBtn.SetText("Close")
	closeBtn.Clicked().Attach(func() { dlg.Close(0) })

	_ = tabs.Pages().Add(page)
}

// ── Quarantine tab ────────────────────────────────────────────────────────────

type quarModel struct {
	walk.TableModelBase
	entries []QuarEntry
}

func (m *quarModel) RowCount() int { return len(m.entries) }
func (m *quarModel) Value(row, col int) interface{} {
	e := m.entries[row]
	switch col {
	case 0:
		return e.OriginalName
	case 1:
		return e.Detail
	case 2:
		if len(e.Sha256) > 16 {
			return e.Sha256[:16] + "…"
		}
		return e.Sha256
	}
	return ""
}

func addQuarTab(dlg *walk.Dialog, tabs *walk.TabWidget, h Handlers) {
	page, _ := walk.NewTabPage()
	_ = page.SetTitle("Quarantine")
	vbl := walk.NewVBoxLayout()
	_ = vbl.SetMargins(walk.Margins{HNear: 8, VNear: 8, HFar: 8, VFar: 8})
	_ = page.SetLayout(vbl)

	model := &quarModel{entries: h.GetQuarantineList()}

	tv, _ := walk.NewTableView(page)
	_ = tv.SetModel(model)
	_ = vbl.SetStretchFactor(tv, 1)

	for _, def := range []struct {
		title string
		width int
	}{
		{"File", 210},
		{"Reason", 270},
		{"SHA256", 140},
	} {
		col := walk.NewTableViewColumn()
		_ = col.SetTitle(def.title)
		_ = col.SetWidth(def.width)
		_ = tv.Columns().Add(col)
	}

	bar := rightAlignedBar(page)

	refreshQBtn, _ := walk.NewPushButton(bar)
	_ = refreshQBtn.SetText("Refresh")
	refreshQBtn.Clicked().Attach(func() {
		model.entries = h.GetQuarantineList()
		model.PublishRowsReset()
	})

	restoreBtn, _ := walk.NewPushButton(bar)
	_ = restoreBtn.SetText("Restore selected")
	restoreBtn.Clicked().Attach(func() {
		idx := tv.CurrentIndex()
		if idx < 0 || idx >= len(model.entries) {
			walk.MsgBox(dlg, "Restore", "Select a file first.", walk.MsgBoxOK|walk.MsgBoxIconInformation)
			return
		}
		entry := model.entries[idx]
		if err := h.RestoreFromQuar(entry.ID); err != nil {
			walk.MsgBox(dlg, "Error", "Restore failed: "+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
			return
		}
		model.entries = h.GetQuarantineList()
		model.PublishRowsReset()
		walk.MsgBox(dlg, "Restored", entry.OriginalName+" restored to its original location.",
			walk.MsgBoxOK|walk.MsgBoxIconInformation)
	})

	_ = tabs.Pages().Add(page)
}

// ── Scan history tab ──────────────────────────────────────────────────────────

type histModel struct {
	walk.TableModelBase
	entries []ScanEntry
}

func (m *histModel) RowCount() int { return len(m.entries) }
func (m *histModel) Value(row, col int) interface{} {
	e := m.entries[row]
	switch col {
	case 0:
		return e.Time
	case 1:
		return e.Name
	case 2:
		return e.Verdict
	case 3:
		return e.Engine
	case 4:
		return e.Detail
	}
	return ""
}

func (m *histModel) StyleCell(style *walk.CellStyle) {
	if style.Col() != 2 || style.Row() >= len(m.entries) {
		return
	}
	switch strings.ToLower(m.entries[style.Row()].Verdict) {
	case "malicious":
		style.BackgroundColor = walk.RGB(220, 53, 69)
		style.TextColor = walk.RGB(255, 255, 255)
	case "suspicious":
		style.BackgroundColor = walk.RGB(255, 193, 7)
		style.TextColor = walk.RGB(0, 0, 0)
	}
}

func addHistTab(tabs *walk.TabWidget, h Handlers) {
	page, _ := walk.NewTabPage()
	_ = page.SetTitle("Scan History")
	vbl := walk.NewVBoxLayout()
	_ = vbl.SetMargins(walk.Margins{HNear: 8, VNear: 8, HFar: 8, VFar: 8})
	_ = page.SetLayout(vbl)

	model := &histModel{entries: h.GetScanHistory()}

	tv, _ := walk.NewTableView(page)
	_ = tv.SetModel(model)
	tv.SetCellStyler(model)
	_ = vbl.SetStretchFactor(tv, 1)

	for _, def := range []struct {
		title string
		width int
	}{
		{"Time", 70},
		{"File", 180},
		{"Verdict", 90},
		{"Engine", 90},
		{"Detail", 220},
	} {
		col := walk.NewTableViewColumn()
		_ = col.SetTitle(def.title)
		_ = col.SetWidth(def.width)
		_ = tv.Columns().Add(col)
	}

	bar := rightAlignedBar(page)
	refreshBtn, _ := walk.NewPushButton(bar)
	_ = refreshBtn.SetText("Refresh")
	refreshBtn.Clicked().Attach(func() {
		model.entries = h.GetScanHistory()
		model.PublishRowsReset()
	})

	_ = tabs.Pages().Add(page)
}

// ── Status tab ────────────────────────────────────────────────────────────────

func addStatusTab(tabs *walk.TabWidget, h Handlers) {
	page, _ := walk.NewTabPage()
	_ = page.SetTitle("Status")
	vbl := walk.NewVBoxLayout()
	_ = vbl.SetMargins(walk.Margins{HNear: 16, VNear: 16, HFar: 16, VFar: 16})
	_ = vbl.SetSpacing(6)
	_ = page.SetLayout(vbl)

	stats := h.GetStats()

	line := func(text string, bold bool) {
		lbl, _ := walk.NewLabel(page)
		_ = lbl.SetText(text)
		if bold {
			if f, err := walk.NewFont("Segoe UI", 9, walk.FontBold); err == nil {
				lbl.SetFont(f)
			}
		}
	}

	yn := func(ok bool, yes, no string) string {
		if ok {
			return "✓ " + yes
		}
		return "✗ " + no
	}

	line("Detection Engines", true)
	line("  VirusTotal:    "+yn(stats.VTEnabled, "Active", "No API key set"), false)
	line("  YARA:          "+yn(stats.YARAEnabled, "Active", "Not compiled in this build"), false)
	line(fmt.Sprintf("  Heuristics:    ✓ Active  (threshold: %d)", stats.HeuristicThresh), false)
	line(fmt.Sprintf("  Blocklist:     ✓ %d hashes loaded", stats.BlocklistCount), false)
	line("", false)
	line(fmt.Sprintf("Cache:  %d verdicts stored", stats.CacheCount), false)

	if len(stats.WatchedFolders) > 0 {
		line("", false)
		line("Watching:", true)
		for _, f := range stats.WatchedFolders {
			line("  "+f, false)
		}
	}

	_, _ = walk.NewVSpacer(page)
	_ = tabs.Pages().Add(page)
}
