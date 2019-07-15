package mdns_test

import (
	"bytes"
	"testing"

	"github.com/ironiridis/klonderoo/mdns"
)

func TestSubjectStringRoundTrip(t *testing.T) {
	tab := []struct {
		instr  string
		err    error
		outstr string
	}{
		{"_exampleservice._tcp.local", nil, "_exampleservice._tcp.local."},
		{"_exampleservice._tcp.local.", nil, "_exampleservice._tcp.local."},
		{"qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwe.", nil, "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwe."},
		{"qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwer.", mdns.IllegalHostnameLabelTooLong, ""},
		{"qwertyuiopqwertyuiopqwertyuiopqwertyu.iopqwertyuiopqwertyuiopqwer.", nil, "qwertyuiopqwertyuiopqwertyuiopqwertyu.iopqwertyuiopqwertyuiopqwer."},
		{"._exampleservice._tcp.local", mdns.IllegalHostnameLabelEmpty, ""},
		{"_exampleservice.._tcp.local", mdns.IllegalHostnameLabelEmpty, ""},
		{"._exampleservice._tcp.local.", mdns.IllegalHostnameLabelEmpty, ""},
		{"_exampleservice.._tcp.local.", mdns.IllegalHostnameLabelEmpty, ""},
	}

	for _, try := range tab {
		s := &mdns.Subject{}
		e := s.FromString(try.instr)
		if e != try.err {
			t.Errorf("Subject.FromString(%q) should have returned %+v, but returned %+v", try.instr, try.err, e)
			continue
		}
		if e != nil {
			continue
		}
		r := s.String()
		if r != try.outstr {
			t.Errorf("Subject.FromString(%q).String() should have returned %q, but returned %q", try.instr, try.outstr, r)
			continue
		}
	}
}

func TestSubjectWireRoundTrip(t *testing.T) {
	tab := []struct {
		str  string
		err1 error
		err2 error
		err3 error
	}{
		{"_exampleservice._tcp.local", nil, nil, nil},
		{"_exampleservice._tcp.local.", nil, nil, nil},
		{"qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwe.", nil, nil, nil},
		{"qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwer.", mdns.IllegalHostnameLabelTooLong, nil, nil},
		{"qwertyuiopqwertyuiopqwertyuiopqwertyu.iopqwertyuiopqwertyuiopqwer.", nil, nil, nil},
		{"._exampleservice._tcp.local", mdns.IllegalHostnameLabelEmpty, nil, nil},
		{"_exampleservice.._tcp.local", mdns.IllegalHostnameLabelEmpty, nil, nil},
		{"._exampleservice._tcp.local.", mdns.IllegalHostnameLabelEmpty, nil, nil},
		{"_exampleservice.._tcp.local.", mdns.IllegalHostnameLabelEmpty, nil, nil},
	}

	for _, try := range tab {
		a := &mdns.Subject{}
		e := a.FromString(try.str)
		if e != try.err1 {
			t.Errorf("Subject.FromString(%q) should have returned %+v, but returned %+v", try.str, try.err1, e)
			continue
		}
		if e != nil {
			continue
		}

		w := bytes.Buffer{}
		e = a.WriteTo(&w)
		if e != try.err2 {
			t.Errorf("Subject.FromString(%q).WriteTo(w) should have returned %+v, but returned %+v", try.str, try.err2, e)
			continue
		}
		if e != nil {
			continue
		}

		b := &mdns.Subject{}
		e = b.ReadFrom(&w)
		if e != try.err3 {
			t.Errorf("Subject.ReadFrom(w) should have returned %+v, but returned %+v", try.err3, e)
			continue
		}
		if e != nil {
			continue
		}

		if !a.EqualTo(b) {
			t.Errorf("Subject.EqualTo() returned false when we expected true")
			continue
		}
	}
}
