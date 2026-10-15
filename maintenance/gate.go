// Copyright 2026 The StuHelper Authors. Licensed under the Apache License, Version 2.0.
package maintenance

import (
	"errors"
	"os"
	"sync/atomic"
	"time"
)

// File is in the existing persistent configuration mount. Only the deployment
// controller creates/removes it; no HTTP endpoint can release the gate.
const File = "/conf/stuhelper-maintenance"

type Gate struct {
	path  string
	ready atomic.Bool
}

func NewGate(path string) *Gate { return &Gate{path: path} }

var Default = NewGate(File)

func (g *Gate) requested() bool {
	_, err := os.Lstat(g.path)
	// Permission/IO errors cannot be interpreted as permission to accept writes.
	return !errors.Is(err, os.ErrNotExist)
}

func (g *Gate) Active() bool { return !g.ready.Load() || g.requested() }

// StartServices keeps background writers and external integrations stopped
// while a restored database is being checked. On an ordinary boot initialization
// remains synchronous, preserving the upstream startup order before HTTP serves.
func (g *Gate) StartServices(start func()) {
	if !g.requested() {
		start()
		g.ready.Store(true)
		return
	}
	go func() {
		for g.requested() {
			time.Sleep(200 * time.Millisecond)
		}
		start()
		g.ready.Store(true)
	}()
}
