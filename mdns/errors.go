package mdns

// Error represents an mDNS client error
type Error string

func (e Error) Error() string { return string(e) }

// Error constants this package can use
const (
	IllegalHostnameLabelTooLong  = Error("hostname contains an illegal label component that is more than 63 bytes")
	IllegalHostnameLabelEmpty    = Error("hostname contains an illegal label component that is empty")
	CannotDecodeRecordType       = Error("unable to decode this record type")
	ResponseReservedBitsHigh     = Error("reserved zero bits not zero")
	ResponseFlagMissing          = Error("decoded header missing response bit")
	OpcodeNotQuery               = Error("decoded opcode wasn't 'query'")
	UnhandledTruncation          = Error("decoded response indicated truncation")
	ResponseCodeFormatError      = Error("server response code indicated Format Error")
	ResponseCodeServerFailure    = Error("server response code indicated Server Failure")
	ResponseCodeNameError        = Error("server response code indicated Name Error")
	ResponseCodeNotImplemented   = Error("server response code indicated Not Implemented")
	ResponseCodeRefused          = Error("server response code indicated Refused")
	ResponseCodeOtherFailure     = Error("server response code indicated failure")
	ResponseQuestionCountNonzero = Error("server response contains nonzero question count")
	ResponseTooLarge             = Error("decoded header advertised more records than permitted")
	RecordParseTypeUnsupported   = Error("cannot parse record due to unsupported type")
	RecordParseLengthUnexpected  = Error("record type has a canonical length but packet disagrees")
)
