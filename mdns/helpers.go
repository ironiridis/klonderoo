package mdns

func uint16ToWire(x uint16) []byte {
	return []byte{byte(x >> 8), byte(x & 0xff)}
}

func wireToUint16(x []byte) uint16 {
	if len(x) < 2 {
		return 0
	}
	return uint16(x[0])<<8 | uint16(x[1])
}
