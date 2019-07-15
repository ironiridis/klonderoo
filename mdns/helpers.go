package mdns

import "io"

// defeat go vet whining about method signatures, because it thinks we are trying to
// implement io.ReaderFrom and io.WriterTo. we aren't (... anymore)
type mDNSReader interface {
	io.Reader
	io.ReaderAt
}
type mDNSWriter interface {
	io.Writer
}

func uint16ToWire(x uint16) []byte {
	return []byte{byte(x >> 8), byte(x & 0xff)}
}

func wireToUint16(x []byte) uint16 {
	if len(x) < 2 {
		return 0
	}
	return uint16(x[0])<<8 | uint16(x[1])
}

func readUint16(r io.Reader) (uint16, error) {
	b := make([]byte, 2)
	n, err := r.Read(b)
	if err != nil {
		return 0, err
	}
	if n < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	return wireToUint16(b), nil
}

func uint32ToWire(x uint32) []byte {
	return []byte{byte(x >> 8), byte(x & 0xff)}
}

func wireToUint32(x []byte) uint32 {
	if len(x) < 4 {
		return 0
	}
	return uint32(x[0])<<24 | uint32(x[1])<<16 | uint32(x[2])<<8 | uint32(x[3])
}

func readUint32(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	n, err := r.Read(b)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	return wireToUint32(b), nil
}
