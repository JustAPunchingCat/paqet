package client

import (
	"context"
	"paqet/internal/tnet"
	"time"
)

func (c *Client) ticker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, iter := range c.iters {
				if iter == nil {
					continue
				}
				for _, tc := range iter.Items {
					if tc == nil {
						continue
					}
					tc.mu.Lock()
					conn := tc.conn
					tc.mu.Unlock()

					if conn != nil {
						go func(cn tnet.Conn) {
							_ = cn.Ping(false)
						}(conn)
					}
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
