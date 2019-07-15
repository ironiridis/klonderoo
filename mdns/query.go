package mdns

import (
	"bytes"
	"net"
	"time"
)

const mDNSMaximumPacketSize = 9000 // rfc6762 section 17

// Client is the main data type of the package.
type Client struct {
	q       *Question
	addr    *net.UDPAddr
	conn    *net.UDPConn
	timeout time.Duration
	maxrecs int
	r       chan<- *Result
}

func (c *Client) readPacket(buf []byte) {
	b := bytes.NewReader(buf)
	r := &Result{maxrecs: c.maxrecs}
	err := r.ReadFrom(b)
	if err != nil {
		return
	}
	c.r <- r
}

func (c *Client) start() (err error) {
	c.addr, err = net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		return
	}

	c.conn, err = net.ListenMulticastUDP("udp4", nil, c.addr)
	if err != nil {
		return
	}
	c.conn.SetDeadline(time.Now().Add(c.timeout))
	c.conn.SetReadBuffer(mDNSMaximumPacketSize)
	_, err = c.conn.WriteToUDP(c.q.Encode(), c.addr)
	if err != nil {
		c.conn.Close()
		return
	}
	go func() {
		defer close(c.r)
		defer c.conn.Close()
		buf := make([]byte, mDNSMaximumPacketSize)
		for {
			n, err := c.conn.Read(buf)
			if err != nil {
				return
			}
			c.readPacket(buf[:n])
		}
	}()
	return nil
}

// NewClient requests, via mDNS, records for host of type t within timeout
func NewClient(host string, t RecordType) (*Client, error) {
	q, err := NewQuestion(host, t)
	if err != nil {
		return nil, err
	}
	c := &Client{q: q, timeout: 5 * time.Second, maxrecs: 1000}
	return c, nil
}

// SetTimeout changes the timeout to a value other than the default of 5 seconds
func (c *Client) SetTimeout(t time.Duration) {
	c.timeout = t
}

// SetMaximumRecords changes the maximum record count to a value other than the
// default of 1000
func (c *Client) SetMaximumRecords(n int) {
	c.maxrecs = n
}

// Run will write the request to the network, and start the thread that awaits
// responses to deliver them on the Result chan.
func (c *Client) Run() (<-chan *Result, error) {
	r := make(chan *Result)
	c.r = r
	err := c.start()
	if err != nil {
		return nil, err
	}
	return r, nil
}
