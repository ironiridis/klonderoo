package mdns

import (
	"bytes"
	"io"
	"strings"
)

// Subject represents a DNS object, domain, or zone name, represented in the
// length-prefixed label series format as described in RFC 1035 sec 4.1.2-3
type Subject struct {
	s []byte
}

// WriteTo will encode Subject and Write it to w
func (s *Subject) WriteTo(w mDNSWriter) error {
	_, err := w.Write(s.s)
	return err
}

// Encode will encode Subject and return it in wire format
func (s *Subject) Encode() []byte {
	return s.s
}

func (s *Subject) labelRead(r mDNSReader) (int64, error) {
	l := make([]byte, 1)
	b := make([]byte, 255)
	var n int
	var err error
	for {
		n, err = r.Read(l)
		if err != nil {
			return -1, err
		}
		if n < 1 {
			return -1, io.ErrUnexpectedEOF
		}
		if l[0]&0xC0 == 0xC0 {
			// label compression
			p := make([]byte, 1)
			n, err = r.Read(p)
			if err != nil {
				return -1, err
			}
			if n != 1 {
				return -1, io.ErrUnexpectedEOF
			}
			return int64(l[0]&0x3f)<<8 | int64(p[0]), nil
		}
		if l[0] > 63 {
			return -1, IllegalHostnameLabelTooLong
		}
		s.s = append(s.s, l...)
		if l[0] == 0 {
			return -1, nil
		}
		n, err = r.Read(b[:l[0]])
		if err != nil {
			return -1, err
		}
		if byte(n) < l[0] {
			return -1, io.ErrUnexpectedEOF
		}
		s.s = append(s.s, b[:n]...)
	}
}

// ReadFrom will decode a Subject by reading it from r
func (s *Subject) ReadFrom(r mDNSReader) error {
	if s.s == nil {
		s.s = make([]byte, 0, 255)
	} else {
		s.s = s.s[:0]
	}
	rdr := r
	for {
		o, err := s.labelRead(rdr)
		if err != nil {
			s.s = nil
			return err
		}
		if o == -1 {
			return nil
		}
		rdr = io.NewSectionReader(r, o, mDNSMaximumPacketSize)
	}
}

// Decode will copy an already-encoded Subject in wire format
func (s *Subject) Decode(buf []byte) error {
	copy(s.s, buf)
	return nil
}

// FromString will build the Subject from a dotted format hostname
func (s *Subject) FromString(str string) error {
	s.s = make([]byte, 0, len(str))

	if str[len(str)-1] == 0x2e {
		// hostname ends with a dot, strip it off, it's implied
		str = str[:len(str)-1]
	}

	for _, lbl := range bytes.Split([]byte(str), []byte(".")) {
		if len(lbl) > 63 {
			s.s = nil
			return IllegalHostnameLabelTooLong
		}
		if len(lbl) == 0 {
			s.s = nil
			return IllegalHostnameLabelEmpty
		}
		s.s = append(s.s, byte(len(lbl)))
		s.s = append(s.s, lbl...)
	}
	s.s = append(s.s, 0x00)
	return nil
}

// String will return the Subject as a printable dotted format hostname
func (s *Subject) String() string {
	if s.s == nil {
		return ""
	}
	var p, l byte
	var str strings.Builder
	str.Grow(len(s.s))
	for s.s[p] != 0 {
		l = s.s[p]
		p++
		str.Write(s.s[p : p+l])
		str.WriteByte(0x2e)
		p += l
	}
	return str.String()
}

// EqualTo compares Subject with another Subject to test for equality
func (s *Subject) EqualTo(c *Subject) bool {
	if s.s == nil || c.s == nil {
		return false
	}
	return bytes.Equal(s.s, c.s)
}
