package mdns

// Result is a response to a Query.
type Result struct {
	QueryHost  string
	Answer     []Record
	Additional []Record
}

// Record is an individual piece of information such as an IP address.
type Record struct {
}

// QueryType represents the different kinds of record types that can be
// requested and returned via mDNS.
type QueryType uint16

// The below record types (and the pseudo-type Any) can be passed to Query.
const (
	RecordTypeA     QueryType = 0x0001
	RecordTypeCNAME QueryType = 0x0005
	RecordTypePTR   QueryType = 0x000c
	RecordTypeTXT   QueryType = 0x0010
	RecordTypeAAAA  QueryType = 0x001c
	RecordTypeSRV   QueryType = 0x0021
	RecordTypeAny   QueryType = 0x00ff
)

// Encode returns the two-byte wire format for this Record Type.
func (t QueryType) Encode() []byte {
	return (uint16ToWire(uint16(t)))
}

func (t QueryType) canDecodeRecord() bool {
	switch t {
	case RecordTypeA, RecordTypeCNAME, RecordTypePTR:
	case RecordTypeSRV, RecordTypeTXT:
		return true
	}
	return false
}
