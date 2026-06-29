//go:build windows

package tray

import (
	"image"
	"image/color"

	"github.com/lxn/walk"
)

type winTray struct {
	h          Handlers
	mw         *walk.MainWindow
	ni         *walk.NotifyIcon
	statusItem *walk.Action
	pauseItem  *walk.Action
	startItem  *walk.Action
}

// New constructs the Windows tray controller.
func New(h Handlers) Tray { return &winTray{h: h} }

func (t *winTray) Run() error {
	mw, err := walk.NewMainWindow()
	if err != nil {
		return err
	}
	t.mw = mw
	// Prevent the hidden main window from exiting the app on WM_CLOSE.
	// Only walk.App().Exit (triggered by Quit/Restart) should end the process.
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		*canceled = true
	})

	ni, err := walk.NewNotifyIcon(mw)
	if err != nil {
		return err
	}
	t.ni = ni
	defer ni.Dispose()

	if icon, err := walk.NewIconFromImageForDPI(shieldImage(), 96); err == nil {
		_ = ni.SetIcon(icon)
	}
	_ = ni.SetToolTip("Windows Defender but Good")

	actions := ni.ContextMenu().Actions()

	t.statusItem = walk.NewAction()
	_ = t.statusItem.SetText("Idle — watching for new downloads")
	_ = t.statusItem.SetEnabled(false)
	_ = actions.Add(t.statusItem)
	_ = actions.Add(walk.NewSeparatorAction())

	t.add(actions, "Scan a file…", t.pickAndScan)
	t.add(actions, "Open dashboard", func() { showDashboard(t.mw, t.h) })
	_ = actions.Add(walk.NewSeparatorAction())

	t.pauseItem = walk.NewAction()
	_ = t.pauseItem.SetText("Pause watching")
	t.pauseItem.SetCheckable(true)
	t.pauseItem.Triggered().Attach(func() {
		t.h.TogglePause()
		t.pauseItem.SetChecked(t.h.IsPaused())
	})
	_ = actions.Add(t.pauseItem)

	if t.h.AutostartSupported {
		t.startItem = walk.NewAction()
		_ = t.startItem.SetText("Start on login")
		t.startItem.SetCheckable(true)
		t.startItem.SetChecked(t.h.IsAutostartEnabled())
		t.startItem.Triggered().Attach(func() {
			t.h.ToggleAutostart()
			t.startItem.SetChecked(t.h.IsAutostartEnabled())
		})
		_ = actions.Add(t.startItem)
	}

	_ = actions.Add(walk.NewSeparatorAction())
	t.add(actions, "Quit", func() {
		t.h.OnQuit()
		walk.App().Exit(0)
	})

	_ = ni.SetVisible(true)
	mw.Run()
	return nil
}

func (t *winTray) pickAndScan() {
	dlg := walk.FileDialog{Title: "Select a file to scan"}
	if ok, err := dlg.ShowOpen(t.mw); err == nil && ok && dlg.FilePath != "" {
		path := dlg.FilePath
		go t.h.ScanPath(path)
	}
}

func (t *winTray) add(actions *walk.ActionList, text string, fn func()) {
	a := walk.NewAction()
	_ = a.SetText(text)
	a.Triggered().Attach(fn)
	_ = actions.Add(a)
}

func (t *winTray) Stop() {
	if t.mw != nil {
		t.mw.Synchronize(func() { walk.App().Exit(0) })
	}
}

func (t *winTray) SetStatus(text string) {
	if t.mw == nil {
		return
	}
	t.mw.Synchronize(func() {
		if t.statusItem != nil {
			_ = t.statusItem.SetText(text)
		}
		_ = t.ni.SetToolTip("Windows Defender but Good: " + text)
	})
}

func (t *winTray) Notify(title, msg string) {
	if t.mw == nil {
		return
	}
	t.mw.Synchronize(func() { _ = t.ni.ShowInfo(title, msg) })
}

// shieldImage builds a simple green icon so we don't ship a binary asset.
func shieldImage() image.Image {
	const n = 32
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	green := color.RGBA{R: 0x2e, G: 0x7d, B: 0x32, A: 0xff}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			img.Set(x, y, green)
		}
	}
	return img
}
