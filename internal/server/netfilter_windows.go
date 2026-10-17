//go:build windows

package server

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"paqet/internal/flog"
)

// createNoWindow keeps netfilter.exe from flashing a console window when
// paqet runs as a background service.
const createNoWindow = 0x08000000

// netfilterRestartDelay is how long to wait before relaunching netfilter.exe
// after an unexpected exit. A dead suppressor silently brings the kernel RSTs
// back, so it is supervised rather than fire-and-forget.
const netfilterRestartDelay = 5 * time.Second

func newNetfilterCmd(path, filter string) *exec.Cmd {
	cmd := exec.Command(path, filter)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	return cmd
}

// spawnNetfilter starts netfilter.exe with the given WinDivert filter and
// supervises it for the lifetime of the server: if it exits, it is relaunched
// with a short backoff until Stop is called.
//
// The first launch is synchronous so a bad path or a missing binary is
// reported to the caller instead of retrying forever in the background.
func spawnNetfilter(path, filter string) (*netfilterProc, error) {
	var (
		mu      sync.Mutex
		current *exec.Cmd
		stopped bool
	)

	first := newNetfilterCmd(path, filter)
	if err := first.Start(); err != nil {
		return nil, fmt.Errorf("start %s with filter %q: %w", path, filter, err)
	}
	current = first

	p := &netfilterProc{}
	p.stop = func() {
		mu.Lock()
		stopped = true
		c := current
		current = nil
		mu.Unlock()
		if c != nil && c.Process != nil {
			// The supervisor goroutine owns Wait(); kill is enough here.
			_ = c.Process.Kill()
		}
	}

	go func() {
		for {
			mu.Lock()
			c := current
			done := stopped
			mu.Unlock()
			if done {
				return
			}

			if c == nil {
				// Previous process exited (or a relaunch failed) — retry.
				time.Sleep(netfilterRestartDelay)

				mu.Lock()
				done = stopped
				mu.Unlock()
				if done {
					return
				}

				next := newNetfilterCmd(path, filter)
				if err := next.Start(); err != nil {
					flog.Errorf("netfilter: relaunch failed: %v (retrying in %s)", err, netfilterRestartDelay)
					continue
				}
				mu.Lock()
				current = next
				mu.Unlock()
				flog.Infof("netfilter: relaunched %s", path)
				continue
			}

			err := c.Wait()

			mu.Lock()
			if current == c {
				current = nil
			}
			done = stopped
			mu.Unlock()
			if done {
				return
			}
			flog.Warnf("netfilter: %s exited (%v) — will relaunch", path, err)
		}
	}()

	return p, nil
}
