package mdns

import "io"

// Record is an individual piece of information such as an IP address.
type Record struct {
	Subject *Subject
	Type    RecordType
	Class   uint16
	TTL     uint32
	Length  uint16
	raw     []byte
	Details RecordInterpreter
}

type RecordInterpreter interface {
	String() string
	parse(mDNSReader, uint16) error
}

type RecordPTR struct {
	Name Subject
}

func (ptr *RecordPTR) String() string {
	return ptr.Name.String()
}
func (ptr *RecordPTR) parse(r mDNSReader, l uint16) error {
	return ptr.Name.ReadFrom(r)
}

type RecordTXT struct {
	Text string
}

func (txt *RecordTXT) String() string {
	return txt.Text
}
func (txt *RecordTXT) parse(r mDNSReader, l uint16) error {
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

// ReadFrom consumes bytes from r and decodes them, which you could probably guess
func (d *Record) ReadFrom(r mDNSReader) (err error) {
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

	d.Length, err = readUint16(r)
	if err != nil {
		return
	}

	switch d.Type {
	case RecordTypePTR:
		{
			d.Details = &RecordPTR{}
			err = d.Details.parse(r, d.Length)
		}
	case RecordTypeTXT:
		{
			d.Details = &RecordTXT{}
			err = d.Details.parse(r, d.Length)
		}
	default:
		{
			var n int
			d.raw = make([]byte, d.Length)
			n, err = r.Read(d.raw)
			if err != nil {
				return
			}
			if n != int(d.Length) {
				err = io.ErrUnexpectedEOF
				return
			}
		}
	}

	return
}
