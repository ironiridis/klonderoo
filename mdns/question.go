package mdns

import (
	"bytes"
	"io"
)

// Question represents an mDNS question
type Question struct {
	TransactionID uint16 // Always zero; mDNS responders don't seem to honor it
	Flags         uint16 // Always zero; no relevant flags wrt mDNS queries
	Subject       *Subject
	QueryType     QueryType // A, AAAA, PTR, TXT, SRV, etc
	QueryClass    uint16
}

// WriteTo encodes the Question and then writes it to w
func (q *Question) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(q.Encode())
	return int64(n), err
}

// Encode will render Question in wire format
func (q *Question) Encode() []byte {
	var b bytes.Buffer
	b.Write(uint16ToWire(q.TransactionID))
	b.Write(uint16ToWire(q.Flags))
	b.Write(uint16ToWire(1)) // question count
	b.Write(uint16ToWire(0)) // answer record count
	b.Write(uint16ToWire(0)) // authority record count
	b.Write(uint16ToWire(0)) // additional record count
	q.Subject.WriteTo(&b)
	b.Write(q.QueryType.Encode())

	return b.Bytes()
}

func (q *Question) Decode(buf []byte) {
}

func NewQuestion(subject string, t QueryType) (*Question, error) {
	q := &Question{Subject: &Subject{}, QueryType: t, QueryClass: 0x0001}
	err := q.Subject.FromString(subject)
	if err != nil {
		return nil, err
	}
	return q, nil
}
