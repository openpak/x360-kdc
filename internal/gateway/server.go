package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net"
)

// Server reads datagrams from one UDP socket and answers them inline.
type Server struct {
	Gateway *Gateway
	Log     *slog.Logger
}

// Serve runs until ctx is cancelled or the socket fails.
func (s *Server) Serve(ctx context.Context, conn *net.UDPConn) error {
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		for _, reply := range s.Gateway.Handle(buf[:n], src) {
			if _, err := conn.WriteToUDPAddrPort(reply, src); err != nil {
				s.Log.Warn("reply failed", "src", src, "err", err)
			}
		}
	}
}
