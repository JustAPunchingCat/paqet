package buffer

import (
	"context"
	"io"
	"strings"
	"sync"
)

func CopyT(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}

// RelayTCP copies data bidirectionally between c1 and c2.
// When either side finishes streaming or closes, it signals the other side so both directions complete cleanly without deadlock.
func RelayTCP(ctx context.Context, c1 io.ReadWriteCloser, c2 io.ReadWriteCloser) error {
	var wg sync.WaitGroup
	wg.Add(2)

	var err1, err2 error

	// Direction 1: c1 -> c2
	go func() {
		defer wg.Done()
		defer c2.Close()
		_, err1 = io.Copy(c2, c1)
	}()

	// Direction 2: c2 -> c1
	go func() {
		defer wg.Done()
		defer c1.Close()
		_, err2 = io.Copy(c1, c2)
	}()

	wg.Wait()

	if err1 != nil && !isNormalClose(err1) {
		return err1
	}
	if err2 != nil && !isNormalClose(err2) {
		return err2
	}
	return nil
}

func isNormalClose(err error) bool {
	if err == nil || err == io.EOF {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "closed pipe") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "forcibly closed")
}
