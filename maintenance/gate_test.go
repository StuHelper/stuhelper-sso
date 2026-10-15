package maintenance

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMaintenanceDefersBackgroundWritersUntilControllerRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate")
	if err := os.WriteFile(path, []byte("transaction"), 0600); err != nil {
		t.Fatal(err)
	}
	gate := NewGate(path)
	started := make(chan struct{})
	complete := make(chan struct{})
	gate.StartServices(func() { close(started); <-complete })
	select {
	case <-started:
		t.Fatal("background writers started before release")
	case <-time.After(30 * time.Millisecond):
	}
	if !gate.Active() {
		t.Fatal("HTTP admission opened during rehearsal")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("background initialization did not resume")
	}
	if !gate.Active() {
		t.Fatal("HTTP admission opened before background initialization completed")
	}
	close(complete)
	deadline := time.Now().Add(time.Second)
	for gate.Active() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if gate.Active() {
		t.Fatal("gate did not open after initialization")
	}
}

func TestMaintenanceOrdinaryBootAndUnreadablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate")
	gate := NewGate(path)
	called := false
	gate.StartServices(func() { called = true })
	if !called || gate.Active() {
		t.Fatal("ordinary startup must initialize synchronously")
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if !gate.Active() {
		t.Fatal("controller freeze did not close admission")
	}
	// A regular parent file produces ENOTDIR, which is not a missing marker.
	broken := NewGate(filepath.Join(path, "marker"))
	broken.ready.Store(true)
	if !broken.Active() {
		t.Fatal("filesystem errors must keep admission closed")
	}
}
