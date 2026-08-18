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

func RelayTCP(ctx context.Context, c1 io.ReadWriteCloser, c2 io.ReadWriteCloser) error {
	_, _, err := RelayTCPStat(ctx, c1, c2)
	return err
}

// RelayTCPStat copies data bidirectionally between c1 and c2 and returns byte counts in both directions.
func RelayTCPStat(ctx context.Context, c1 io.ReadWriteCloser, c2 io.ReadWriteCloser) (n1 int64, n2 int64, err error) {
	var wg sync.WaitGroup
	wg.Add(2)

	var err1, err2 error

	// Direction 1: c1 -> c2 (client to remote)
	go func() {
		defer wg.Done()
		defer c2.Close()
		n1, err1 = io.Copy(c2, c1)
	}()

	// Direction 2: c2 -> c1 (remote to client)
	go func() {
		defer wg.Done()
		defer c1.Close()
		n2, err2 = io.Copy(c1, c2)
	}()

	wg.Wait()

	if err1 != nil && !isNormalClose(err1) {
		return n1, n2, err1
	}
	if err2 != nil && !isNormalClose(err2) {
		return n1, n2, err2
	}
	return n1, n2, nil
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
