package ldap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
)

// SASLSecurityMode controls SASL security layer after NTLM bind.
// Values match RFC 4752 security layer bitmask and can be used directly
// as the SASL security layer byte on the wire.
type SASLSecurityMode int

const (
	// SASLSecurityNone disables SASL wrapping. Subsequent LDAP messages are
	// sent as plain BER. This works only when the server does not require
	// LDAP signing.
	SASLSecurityNone SASLSecurityMode = 0

	// SASLSecuritySign enables SASL integrity protection (RFC 4752 bit 1).
	// AD always seals LDAP SASL traffic when NTLM integrity is negotiated,
	// so for NTLM this is functionally equivalent to SASLSecuritySeal.
	SASLSecuritySign SASLSecurityMode = 2

	// SASLSecuritySeal enables SASL confidentiality and integrity
	// (RFC 4752 bit 2). Messages are encrypted and integrity-protected.
	SASLSecuritySeal SASLSecurityMode = 4
)

// maxSASLPayload is the maximum SASL-wrapped message size we accept (16 MB).
const maxSASLPayload = 16 * 1024 * 1024

// saslReadBuffer buffers unwrapped plaintext from a single SASL frame and
// serves it incrementally to callers (typically bufio.NewReader + ber.ReadPacket).
type saslReadBuffer struct {
	buf []byte
	pos int
}

// serve copies buffered plaintext into p. Returns the byte count and true if
// data was available, or 0 and false when the buffer is empty.
func (b *saslReadBuffer) serve(p []byte) (int, bool) {
	if b.pos >= len(b.buf) {
		return 0, false
	}
	n := copy(p, b.buf[b.pos:])
	b.pos += n
	if b.pos >= len(b.buf) {
		b.buf = nil
		b.pos = 0
	}
	return n, true
}

// store replaces the buffer contents and resets the read position.
func (b *saslReadBuffer) store(data []byte) {
	b.buf = data
	b.pos = 0
}

// saslConn wraps a net.Conn with NTLM SASL framing. Each LDAP message on the
// wire becomes a 4-byte big-endian length prefix followed by the wrapped data
// in the format [16-byte MAC][ciphertext]. AD always seals LDAP SASL traffic
// when NTLM integrity is negotiated, so a single Seal/Unseal path handles
// both SASLSecuritySign and SASLSecuritySeal.
type saslConn struct {
	conn    net.Conn
	session *ntlmssp.Session

	// write side
	wSeqNum uint32
	wMu     sync.Mutex

	// read side
	rBuf    saslReadBuffer
	rSeqNum uint32
	rMu     sync.Mutex
}

var _ net.Conn = (*saslConn)(nil)

func newSASLConn(conn net.Conn, session *ntlmssp.Session) *saslConn {
	return &saslConn{
		conn:    conn,
		session: session,
	}
}

// Write wraps p (a complete BER-encoded LDAP message) in a SASL frame and
// writes it to the underlying connection.
func (s *saslConn) Write(p []byte) (int, error) {
	s.wMu.Lock()
	defer s.wMu.Unlock()

	// AD always seals LDAP SASL traffic when NTLM integrity is
	// negotiated, so both Sign and Seal use Seal/Unseal framing:
	// [16-byte MAC][ciphertext].
	sealed, newSeq := s.session.Seal(nil, p, s.wSeqNum)
	s.wSeqNum = newSeq

	// Build frame: [4-byte BE length][wrapped data]
	frame := make([]byte, 4+len(sealed))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(sealed)))
	copy(frame[4:], sealed)

	_, err := s.conn.Write(frame)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read serves unwrapped plaintext to the caller. Internally it reads complete
// SASL frames from the underlying connection, unwraps them, and buffers the
// plaintext. The caller (typically bufio.NewReader + ber.ReadPacket) may
// request arbitrary byte counts.
func (s *saslConn) Read(p []byte) (int, error) {
	s.rMu.Lock()
	defer s.rMu.Unlock()

	if n, ok := s.rBuf.serve(p); ok {
		return n, nil
	}

	// Read a complete SASL frame.
	var hdr [4]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return 0, err
	}
	msgLen := binary.BigEndian.Uint32(hdr[:])
	if msgLen > maxSASLPayload {
		return 0, fmt.Errorf("ldap: SASL frame too large (%d bytes)", msgLen)
	}

	wrapped := make([]byte, msgLen)
	if _, err := io.ReadFull(s.conn, wrapped); err != nil {
		return 0, err
	}

	// AD always seals LDAP SASL traffic when NTLM integrity is
	// negotiated, so both Sign and Seal use Seal/Unseal framing:
	// [16-byte MAC][ciphertext].
	plaintext, newSeq, err := s.session.Unseal(nil, wrapped, s.rSeqNum)
	if err != nil {
		return 0, fmt.Errorf("ldap: SASL unseal failed: %w", err)
	}
	s.rSeqNum = newSeq

	s.rBuf.store(plaintext)
	n, _ := s.rBuf.serve(p)
	return n, nil
}

// Delegate remaining net.Conn methods to the underlying connection.
func (s *saslConn) Close() error                       { return s.conn.Close() }
func (s *saslConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *saslConn) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *saslConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *saslConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *saslConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
