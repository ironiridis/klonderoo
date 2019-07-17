package mdns

import "io"

// Because of message compression (RFC1035 sec 4.1.4) we need to be able to
// read not just the packet as it arrives, but also random unknown offsets in
// the DNS packet. Therefore we need io.ReaderAt.
type mDNSPacketReader interface {
	io.Reader
	io.ReaderAt
}

// We also have some methods we call "WriteTo", which accepts an io.Writer. As
// it happens, `go vet` will warn on our non-standard use of a well-known method
// since we don't bother returning the number of bytes. Calling io.Writer some
// other name allows us to silence this warning, since it doesn't apply.
// We only ever use WriteTo to write to a buffer, so that packet in turn can be
// flushed all at once. If we really felt compelled we could just pass in the
// buffer instead of a generic Writer. 🤷‍
// This behavior of `go vet` is kind of frustrating, since interfaces already
// enforce the method signature contract. Is this solving a real problem?
type mDNSPacketWriter interface {
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
