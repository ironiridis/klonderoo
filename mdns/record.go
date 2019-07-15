package mdns

// Record is an individual piece of information such as an IP address.
type Record struct {
	Subject *Subject
	Type    QueryType
	Class   uint16
	TTL     uint32
	Length  uint16
	raw     []byte
}

// ReadFrom consumes bytes from r and decodes them, which you could probably guess
func (d *Record) ReadFrom(r mDNSReader) error {
	d.Subject = &Subject{}
	err := d.Subject.ReadFrom(r)
	if err != nil {
		return err
	}

	t, err := readUint16(r)
	if err != nil {
		return err
	}
	d.Type = QueryType(t)
	if !d.Type.canDecodeRecord() {
		return CannotDecodeRecordType
	}

	d.Class, err = readUint16(r)
	if err != nil {
		return err
	}
	if d.Class != 0x0001 {
		return ClassNotInternet
	}

	d.TTL, err = readUint32(r)
	if err != nil {
		return err
	}

	d.Length, err = readUint16(r)
	if err != nil {
		return err
	}

	return nil
}
