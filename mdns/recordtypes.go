package mdns

import (
	"fmt"
	"io"
	"net"
)

// RecordType represents the different kinds of record types that can be
// requested and returned via mDNS.
type RecordType uint16

// These record types (and the pseudo-type Any) can be passed to Query.
const (
	RecordTypeA     RecordType = 0x0001
	RecordTypeCNAME RecordType = 0x0005
	RecordTypePTR   RecordType = 0x000c
	RecordTypeTXT   RecordType = 0x0010
	RecordTypeAAAA  RecordType = 0x001c
	RecordTypeSRV   RecordType = 0x0021
	RecordTypeAny   RecordType = 0x00ff
)

func (t RecordType) encode() []byte {
	return (uint16ToWire(uint16(t)))
}

func (t RecordType) parser() (ParseableRecord, error) {
	switch t {
	case RecordTypeA:
		return &RecordA{}, nil
	case RecordTypeCNAME:
		return &RecordCNAME{}, nil
	case RecordTypePTR:
		return &RecordPTR{}, nil
	case RecordTypeTXT:
		return &RecordTXT{}, nil
	case RecordTypeAAAA:
		return &RecordAAAA{}, nil
	case RecordTypeSRV:
		return &RecordSRV{}, nil
	}
	return nil, RecordParseTypeUnsupported

}

func (t RecordType) String() string {
	switch t {
	case RecordTypeA:
		return "A"
	case RecordTypeCNAME:
		return "CNAME"
	case RecordTypePTR:
		return "PTR"
	case RecordTypeTXT:
		return "TXT"
	case RecordTypeAAAA:
		return "AAAA"
	case RecordTypeSRV:
		return "SRV"
	case RecordTypeAny:
		return "Any"
	}
	return fmt.Sprintf("[%04x]", uint16(t))
}

// RecordPTR is a decoded PTR record.
type RecordPTR struct {
	Name Subject
}

// RecordTXT is a decoded TXT record. Note that TXT records are free-form
// and it's up to the application to decide what their content represent.
type RecordTXT struct {
	Text string
}

// RecordA is a decoded A record, holding an IPv4 address.
type RecordA struct {
	Addr net.IP
}

// RecordCNAME is a decoded CNAME record.
type RecordCNAME struct {
	CanonicalName Subject
}

// RecordAAAA is a decoded AAAA record, holding an IPv6 address.
type RecordAAAA struct {
	Addr net.IP
}

// RecordSRV is a decoded SRV record.
type RecordSRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   Subject
}

func (ptr *RecordPTR) String() string {
	return ptr.Name.String()
}
func (ptr *RecordPTR) parse(r mDNSPacketReader, l uint16) error {
	return ptr.Name.ReadFrom(r)
}
func (txt *RecordTXT) String() string {
	return txt.Text
}
func (txt *RecordTXT) parse(r mDNSPacketReader, l uint16) error {
	b := make([]byte, l)
	n, err := r.Read(b)
	if err != nil {
		return err
	}
	if n < int(l) {
		return io.ErrUnexpectedEOF
	}
	txt.Text = string(b[:n])
	return nil
}
func (cnm *RecordCNAME) String() string {
	return cnm.CanonicalName.String()
}
func (cnm *RecordCNAME) parse(r mDNSPacketReader, l uint16) error {
	return cnm.CanonicalName.ReadFrom(r)
}
func (a *RecordA) String() string {
	return a.Addr.String()
}
func (a *RecordA) parse(r mDNSPacketReader, l uint16) error {
	if l != 4 {
		return RecordParseLengthUnexpected
	}
	b := make([]byte, 4)
	n, err := r.Read(b)
	if err != nil {
		return err
	}
	if n != 4 {
		return io.ErrUnexpectedEOF
	}
	a.Addr = net.IPv4(b[0], b[1], b[2], b[3])
	return nil
}
func (a *RecordAAAA) String() string {
	return a.Addr.String()
}
func (a *RecordAAAA) parse(r mDNSPacketReader, l uint16) error {
	if l != 16 {
		return RecordParseLengthUnexpected
	}
	b := make([]byte, 16)
	n, err := r.Read(b)
	if err != nil {
		return err
	}
	if n != 16 {
		return io.ErrUnexpectedEOF
	}
	copy(a.Addr, b)
	return nil
}
func (srv *RecordSRV) String() string {
	return fmt.Sprintf("pri=%d weight=%d port=%d target=%q", srv.Priority, srv.Weight, srv.Port, srv.Target.String())
}
func (srv *RecordSRV) parse(r mDNSPacketReader, l uint16) error {
	var err error
	srv.Priority, err = readUint16(r)
	if err != nil {
		return err
	}
	srv.Weight, err = readUint16(r)
	if err != nil {
		return err
	}
	srv.Port, err = readUint16(r)
	if err != nil {
		return err
	}
	err = srv.Target.ReadFrom(r)
	if err != nil {
		return err
	}

	return nil
}
