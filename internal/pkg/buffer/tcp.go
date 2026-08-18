package buffer

import (
	"context"
	"io"
	"sync"
)

func CopyT(dst io.Writer, src io.Reader) error {
	bufp := TPool.Get().(*[]byte)
	defer TPool.Put(bufp)
	buf := *bufp

	_, err := io.CopyBuffer(dst, src, buf)
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
		err1 = CopyT(c2, c1)
	}()

	// Direction 2: c2 -> c1
	go func() {
		defer wg.Done()
		defer c1.Close()
		err2 = CopyT(c1, c2)
	}()

	wg.Wait()

	if err1 != nil && err1 != io.EOF {
		return err1
	}
	if err2 != nil && err2 != io.EOF {
		return err2
	}
	return nil
}
