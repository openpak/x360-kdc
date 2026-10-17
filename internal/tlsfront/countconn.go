package tlsfront

import (
	"net"
	"sync/atomic"
	"time"
)

// CountingListener logs, when each connection closes, how many bytes went
// each way and for how long: a client that gives up during the handshake shows
// up as a short exchange with no request.
type CountingListener struct {
	net.Listener
	Log func(msg string, args ...any)
}

func (l *CountingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &countConn{Conn: c, log: l.Log, start: time.Now()}, nil
}

type countConn struct {
	net.Conn
	log     func(string, ...any)
	start   time.Time
	in, out atomic.Int64
	closed  atomic.Bool
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.in.Add(int64(n))
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.out.Add(int64(n))
	return n, err
}

func (c *countConn) Close() error {
	if !c.closed.Swap(true) && c.log != nil {
		c.log("tls conn closed", "remote", c.RemoteAddr().String(), "bytes_in", c.in.Load(), "bytes_out", c.out.Load(),
			"ms", time.Since(c.start).Milliseconds())
	}
	return c.Conn.Close()
}
