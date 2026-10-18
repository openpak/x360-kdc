package kdc

import (
	"context"
	"errors"
	"log/slog"
	"net"
)

// Server reads datagrams from one UDP socket and answers them inline. Each
// datagram costs at most one RSA-2048 decryption and two RSA verifications,
// so nothing slow sits on the receive loop.
type Server struct {
	Handler *Handler
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
		reply, res, err := s.Handler.Handle(buf[:n])
		attrs := []any{"kind", string(res.Kind), "src", src, "len", n}
		attrs = append(attrs, res.Attrs...)
		if err != nil {
			s.Log.Info("rejected", append(attrs, "err", err.Error())...)
			continue
		}
		if reply == nil {
			s.Log.Info("recorded, no reply", attrs...)
			continue
		}
		if _, err := conn.WriteToUDPAddrPort(reply, src); err != nil {
			s.Log.Warn("reply failed", append(attrs, "err", err)...)
			continue
		}
		s.Log.Info("answered", append(attrs, "reply_len", len(reply))...)
	}
}
