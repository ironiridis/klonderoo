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
	Type          RecordType // A, AAAA, PTR, TXT, SRV, etc
	Class         uint16
}

// WriteTo encodes Question and then writes it to w
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
	b.Write(q.Type.encode())
	b.Write(uint16ToWire(q.Class))

	return b.Bytes()
}

// NewQuestion takes a subject and a query type and returns an initialized Question
func NewQuestion(subject string, t RecordType) (*Question, error) {
	q := &Question{Subject: &Subject{}, Type: t, Class: 0x0001}
	err := q.Subject.FromString(subject)
	if err != nil {
		return nil, err
	}
	return q, nil
}
