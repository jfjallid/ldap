package gssapi

// SASLWrapper wraps and unwraps messages for a SASL security layer. It has the
// same shape as ldap.SASLSession (declared here to avoid an import cycle), plus
// SealErr so a wrapping failure is reported rather than sent as an empty frame.
type SASLWrapper interface {
	Seal(dst, plaintext []byte, seqNum uint32) ([]byte, uint32)
	SealErr(dst, plaintext []byte, seqNum uint32) ([]byte, uint32, error)
	Unseal(dst, wrapped []byte, seqNum uint32) ([]byte, uint32, error)
	Close() error
}
