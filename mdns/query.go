package mdns

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

// Client is the main data type of the package.
type Client struct {
	q       *Question
	addr    *net.UDPAddr
	conn    *net.UDPConn
	timeout time.Duration
	r       chan<- *Result
}

func (c *Client) readPacket(buf []byte) {
	fmt.Printf("%q\n", buf)
	b := bytes.NewBuffer(buf)
	r := &Result{}
	if b.Len() < 12 { // not enough bytes for a complete header
		return
	}
	hdr := b.Next(12)
	if hdr[2]&0x80 == 0 { // header indicates a query, not a response
		return
	}
	if hdr[2]&0x70 != 0 { // opcode is not "query"
		return
	}
	if hdr[3]&0x0f != 0 { // response code is not "no error"
		return
	}

	// store record counts
	// parse question section
	// validate that question response equals our original query
	// parse answer section
	// store answer records
	// parse authority section
	// ignore?
	// parse additional record section
	// store additional records

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
	c.conn.SetReadBuffer(9000) // rfc6762 sec 17 maximum size
	_, err = c.conn.WriteToUDP(c.q.Encode(), c.addr)
	if err != nil {
		c.conn.Close()
		return
	}
	go func() {
		defer close(c.r)
		defer c.conn.Close()
		buf := make([]byte, 9000)
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
func NewClient(host string, t QueryType) (*Client, error) {
	q, err := NewQuestion(host, t)
	if err != nil {
		return nil, err
	}
	c := &Client{q: q, timeout: 5 * time.Second}
	return c, nil
}

// SetTimeout changes the timeout to a value other than the default of 5 seconds
func (c *Client) SetTimeout(t time.Duration) {
	c.timeout = t
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
