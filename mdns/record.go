package mdns

import (
	"fmt"
	"io"
)

// Record is an individual piece of information such as an IP address.
type Record struct {
	Subject *Subject
	Type    RecordType
	Class   uint16
	TTL     uint32
	length  uint16
	Value   ParseableRecord
}

// ParseableRecord is an interface for holding records that can be parsed by
// this package.
type ParseableRecord interface {
	String() string
	parse(mDNSPacketReader, uint16) error
}

// readFrom consumes bytes from r and decodes them, which you could probably guess
func (d *Record) readFrom(r mDNSPacketReader) (err error) {
	d.Subject = &Subject{}
	err = d.Subject.ReadFrom(r)
	if err != nil {
		return
	}

	t, err := readUint16(r)
	if err != nil {
		return
	}
	d.Type = RecordType(t)

	d.Class, err = readUint16(r)
	if err != nil {
		return
	}

	d.TTL, err = readUint32(r)
	if err != nil {
		return
	}

	d.length, err = readUint16(r)
	if err != nil {
		return
	}
	d.Value, err = d.Type.parser()
	if err == nil && d.Value != nil {
		d.Value.parse(r, d.length)
	} else {
		var n int
		raw := make([]byte, d.length)
		n, err = r.Read(raw)
		if err != nil {
			return
		}
		if n != int(d.length) {
			err = io.ErrUnexpectedEOF
			return
		}
		fmt.Printf("unparsed record %v: %02x\n", d.Type, raw)
	}
	return
}
