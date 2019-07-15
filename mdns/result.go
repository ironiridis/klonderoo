package mdns

// Result is a response to a Query.
type Result struct {
	TransactionID uint16 // Always zero; mDNS responders don't seem to honor it
	Flags         uint16 // Success is 0x8000 (usually)
	Answer        []Record
	Additional    []Record
}

func (d *Result) validateFlags() error {
	if d.Flags&0x8000 != 0x8000 {
		return ResponseFlagMissing
	}
	if d.Flags&0x7800 != 0x0000 {
		return OpcodeNotQuery
	}
	if d.Flags&0x0070 != 0x0000 {
		return ResponseReservedBitsHigh
	}
	switch d.Flags & 0x000f {
	case 0:
		return nil
	case 1:
		return ResponseCodeFormatError
	case 2:
		return ResponseCodeServerFailure
	case 3:
		return ResponseCodeNameError
	case 4:
		return ResponseCodeNotImplemented
	case 5:
		return ResponseCodeRefused
	default:
		return ResponseCodeOtherFailure
	}

}

func (d *Result) ReadFrom(r mDNSReader) (err error) {
	d.TransactionID, err = readUint16(r)
	if err != nil {
		return
	}
	d.Flags, err = readUint16(r)
	if err != nil {
		return
	}
	err = d.validateFlags()
	if err != nil {
		return
	}
	qdcount, err := readUint16(r)
	if err != nil {
		return
	}
	if qdcount > 0 {
		err = ResponseQuestionCountNonzero
		return
	}
	ancount, err := readUint16(r)
	if err != nil {
		return
	}
	nscount, err := readUint16(r)
	if err != nil {
		return
	}
	arcount, err := readUint16(r)
	if err != nil {
		return
	}

	for ancount > 0 {
		ancount--
		rec := Record{}
		err = rec.ReadFrom(r)
		if err != nil {
			return
		}
		d.Answer = append(d.Answer, rec)
	}
	for nscount > 0 {
		nscount--
		rec := Record{}
		err = rec.ReadFrom(r)
		if err != nil {
			return
		}
		// records are discarded
	}
	for arcount > 0 {
		arcount--
		rec := Record{}
		err = rec.ReadFrom(r)
		if err != nil {
			return
		}
		d.Additional = append(d.Additional, rec)
	}
	return nil
}
