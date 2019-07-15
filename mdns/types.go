package mdns

import "fmt"

// RecordType represents the different kinds of record types that can be
// requested and returned via mDNS.
type RecordType uint16

// The below record types (and the pseudo-type Any) can be passed to Query.
const (
	RecordTypeA     RecordType = 0x0001
	RecordTypeCNAME RecordType = 0x0005
	RecordTypePTR   RecordType = 0x000c
	RecordTypeTXT   RecordType = 0x0010
	RecordTypeAAAA  RecordType = 0x001c
	RecordTypeSRV   RecordType = 0x0021
	RecordTypeAny   RecordType = 0x00ff
)

// Encode returns the two-byte wire format for this Record Type.
func (t RecordType) Encode() []byte {
	return (uint16ToWire(uint16(t)))
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
