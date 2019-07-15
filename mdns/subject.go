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

// ReadFrom will decode a Subject by reading it from r
func (s *Subject) ReadFrom(r mDNSReader) (err error) {
	s.s = s.s[:0]
	l := make([]byte, 1)
	b := make([]byte, 255)
	var n int
	for {
		n, err = r.Read(l)
		if err != nil {
			s.s = nil
			return
		}
		if n < 1 {
			s.s = nil
			err = io.ErrUnexpectedEOF
			return
		}
		if n >= 192 {
			s.s = nil
			err = LabelCompressionNotSupported
			return
		}
		if n > 63 {
			s.s = nil
			err = IllegalHostnameLabelTooLong
			return
		}
		s.s = append(s.s, l...)
		if l[0] == 0 {
			break
		}
		_, err = r.Read(b[:l[0]])
		if err != nil {
			s.s = nil
			return
		}
		if byte(n) < l[0] {
			s.s = nil
			err = io.ErrUnexpectedEOF
			return
		}
		s.s = append(s.s, b[:n]...)
	}
	return
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
