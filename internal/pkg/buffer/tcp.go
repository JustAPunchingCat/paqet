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

// RelayTCP copies data bidirectionally between local and remote streams with full-duplex coordination.
// It allows download to stream completely even when upload finishes early, and cleanly tears down on errors.
func RelayTCP(ctx context.Context, local io.ReadWriteCloser, remote io.ReadWriteCloser) error {
	var wg sync.WaitGroup
	wg.Add(1)

	var uploadErr, downloadErr error

	// Upload: local -> remote (Client sends request/data to server)
	go func() {
		uploadErr = CopyT(remote, local)
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		if uploadErr != nil && uploadErr != io.EOF {
			// If upload fails with a real network error, abort both sides
			_ = local.Close()
			_ = remote.Close()
		}
	}()

	// Download: remote -> local (Server sends response/data to client)
	go func() {
		defer wg.Done()
		downloadErr = CopyT(local, remote)
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = local.Close()
		}
		_ = remote.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		_ = local.Close()
		_ = remote.Close()
		if downloadErr != nil && downloadErr != io.EOF {
			return downloadErr
		}
		if uploadErr != nil && uploadErr != io.EOF {
			return uploadErr
		}
		return nil
	case <-ctx.Done():
		_ = local.Close()
		_ = remote.Close()
		return ctx.Err()
	}
}
