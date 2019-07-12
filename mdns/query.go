package mdns

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

// Result is an individual PTR response to a Query
type Result struct {
	PTRName  string
	TXTLines []string
	SRVLines []string
	ALines   []string
}

type queryRoutine struct {
	host     string
	unicast  bool
	qtype    [2]byte
	addr     *net.UDPAddr
	conn     *net.UDPConn
	deadline time.Time
	r        chan<- *Result
}

func (q *queryRoutine) send() (int, error) {
	var b bytes.Buffer
	b.Grow(len(q.host) + 18)
	b.Write([]byte{0x00, 0x00}) // transaction ID (nonzero seems to be ignored 😢)
	b.Write([]byte{0x00, 0x00}) // QR=0 Op=0000 AA=0 TC=0 RD=0 RA=0 Z=000 RC=0000
	b.Write([]byte{0x00, 0x01}) // question count: 1
	b.Write([]byte{0x00, 0x00}) // answer record count: 0
	b.Write([]byte{0x00, 0x00}) // authority record count: 0
	b.Write([]byte{0x00, 0x00}) // additional record count: 0

	for _, lbl := range bytes.Split([]byte(q.host), []byte(".")) {
		if len(lbl) > 63 || len(lbl) == 0 {
			return 0, fmt.Errorf("hostname %q contains illegal label %q", q.host, lbl)
		}
		b.WriteByte(byte(len(lbl)))
		b.Write(lbl)
	}
	b.WriteByte(0x00) // end of labels

	b.Write(q.qtype[:]) // query type: ptr, a, aaaa, etc
	if q.unicast {
		b.WriteByte(0x80) // unicast reply preferred flag
	} else {
		b.WriteByte(0x00) // multicast reply is ok
	}
	b.WriteByte(0x01) // question class: internet

	return q.conn.WriteToUDP(b.Bytes(), q.addr)
}

func (q *queryRoutine) readPacket(buf []byte) {
	q.r <- &Result{}
	fmt.Printf("wow:\n%q\n", buf)
}

func (q *queryRoutine) start(d time.Duration) {
	var err error
	defer close(q.r)
	if len(q.host) < 1 {
		return
	}
	if q.host[len(q.host)-1] == 0x2e {
		// hostname ends with a dot, strip it off, it's implied
		q.host = q.host[:len(q.host)-1]
	}

	q.deadline = time.Now().Add(d)
	q.addr, err = net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		return
	}

	q.conn, err = net.ListenMulticastUDP("udp4", nil, q.addr)
	if err != nil {
		return
	}
	defer q.conn.Close()
	q.conn.SetDeadline(q.deadline)
	q.conn.SetReadBuffer(9000) // rfc6762 sec 17 maximum size
	_, err = q.send()
	if err != nil {
		return
	}
	buf := make([]byte, 9000)
	for {
		n, err := q.conn.Read(buf)
		if err != nil {
			return
		}
		q.readPacket(buf[:n])
	}
}

// QueryA requests, via mDNS, the IPv4 address of host
func QueryA(host string, unicast bool, timeout time.Duration) <-chan *Result {
	r := make(chan *Result)
	x := &queryRoutine{
		host:    host,
		unicast: unicast,
		qtype:   [2]byte{0x00, 0x01},
		r:       r,
	}
	go x.start(timeout)
	return r
}

// QueryAAAA requests, via mDNS, the IPv6 address of host
func QueryAAAA(host string, unicast bool, timeout time.Duration) <-chan *Result {
	r := make(chan *Result)
	x := &queryRoutine{
		host:    host,
		unicast: unicast,
		qtype:   [2]byte{0x00, 0x1C},
		r:       r,
	}
	go x.start(timeout)
	return r
}

// QueryPTR requests, via mDNS, pointer records for host
func QueryPTR(host string, unicast bool, timeout time.Duration) <-chan *Result {
	r := make(chan *Result)
	x := &queryRoutine{
		host:    host,
		unicast: unicast,
		qtype:   [2]byte{0x00, 0x0C},
		r:       r,
	}
	go x.start(timeout)
	return r
}

// QueryTXT requests, via mDNS, text records for host
func QueryTXT(host string, unicast bool, timeout time.Duration) <-chan *Result {
	r := make(chan *Result)
	x := &queryRoutine{
		host:    host,
		unicast: unicast,
		qtype:   [2]byte{0x00, 0x10},
		r:       r,
	}
	go x.start(timeout)
	return r
}
