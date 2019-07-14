package mdns

// Error represents an mDNS client error
type Error string

func (e Error) Error() string { return string(e) }

// Error constants this package can use
const (
	IllegalHostnameLabelTooLong  = Error("hostname contains an illegal label component that is more than 63 bytes")
	IllegalHostnameLabelEmpty    = Error("hostname contains an illegal label component that is empty")
	LabelCompressionNotSupported = Error("label compression is not supported")
)
