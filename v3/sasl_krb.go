package ldap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jfjallid/gokrb5/v8/crypto"
	krbgssapi "github.com/jfjallid/gokrb5/v8/gssapi"
	"github.com/jfjallid/gokrb5/v8/iana/keyusage"
	"github.com/jfjallid/gokrb5/v8/types"
)

// krbSASLConn wraps a net.Conn with Kerberos GSSAPI SASL framing.
// Each LDAP message on the wire becomes a 4-byte big-endian length prefix
// followed by a GSS WrapToken (RFC 4121). Supports both integrity-only
// (sign) and confidentiality (seal) modes.
type krbSASLConn struct {
	conn   net.Conn
	subkey types.EncryptionKey
	mode   SASLSecurityMode

	// write side
	wSeqNum uint64
	wMu     sync.Mutex

	// read side
	rBuf    saslReadBuffer
	rSeqNum uint64
	rMu     sync.Mutex
}

var _ net.Conn = (*krbSASLConn)(nil)

func newKrbSASLConn(conn net.Conn, keyType int32, keyValue []byte, mode SASLSecurityMode) *krbSASLConn {
	return &krbSASLConn{
		conn: conn,
		subkey: types.EncryptionKey{
			KeyType:  keyType,
			KeyValue: keyValue,
		},
		mode: mode,
		// Sequence numbers start at 0 for the initiator after the bind.
		// The bind itself used SndSeqNum 1 for the NegotiateSaslAuth token,
		// so post-bind data starts at 2.
		wSeqNum: 2,
		rSeqNum: 0,
	}
}

// Write wraps p (a complete BER-encoded LDAP message) in a Kerberos GSSAPI
// SASL frame and writes it to the underlying connection.
func (s *krbSASLConn) Write(p []byte) (int, error) {
	s.wMu.Lock()
	defer s.wMu.Unlock()

	var wireBytes []byte
	var err error

	if s.mode == SASLSecuritySeal {
		wireBytes, err = s.sealWrite(p)
	} else {
		wireBytes, err = s.signWrite(p)
	}
	if err != nil {
		return 0, err
	}
	s.wSeqNum++

	// Build SASL frame: [4-byte BE length][wire bytes]
	frame := make([]byte, 4+len(wireBytes))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(wireBytes)))
	copy(frame[4:], wireBytes)

	if _, err := s.conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// signWrite builds a WrapToken with integrity-only protection.
func (s *krbSASLConn) signWrite(p []byte) ([]byte, error) {
	encType, err := crypto.GetEtype(s.subkey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL write: %w", err)
	}

	// Flags: acceptor_subkey=1, sealed=0, from_acceptor=0
	token := &krbgssapi.WrapToken{
		Flags:     krbgssapi.MICTokenFlagAcceptorSubkey,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: s.wSeqNum,
		Payload:   p,
	}

	if err := token.SetCheckSum(s.subkey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL checksum: %w", err)
	}

	wireBytes, err := token.Marshal()
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL marshal: %w", err)
	}
	return wireBytes, nil
}

// sealWrite builds a WrapToken with confidentiality (encryption + integrity).
// Per RFC 4121 §4.2.4: encrypt(plaintext || header_copy) with EC=0, RRC=0.
func (s *krbSASLConn) sealWrite(p []byte) ([]byte, error) {
	encType, err := crypto.GetEtype(s.subkey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL write: %w", err)
	}

	// Build the 16-byte GSS header with EC=0, RRC=0 for encryption input.
	// Flags: acceptor_subkey=1, sealed=1, from_acceptor=0
	flags := krbgssapi.MICTokenFlagAcceptorSubkey | krbgssapi.MICTokenFlagSealed
	header := make([]byte, krbgssapi.HdrLen)
	header[0] = 0x05
	header[1] = 0x04
	header[2] = byte(flags)
	header[3] = krbgssapi.FillerByte
	// EC=0, RRC=0 (bytes 4-7 are already zero)
	binary.BigEndian.PutUint64(header[8:16], s.wSeqNum)

	// Construct plaintext: data || header (no filler since EC=0).
	plain := make([]byte, len(p)+krbgssapi.HdrLen)
	copy(plain, p)
	copy(plain[len(p):], header)

	// Encrypt with the etype's EncryptMessage which prepends a confounder
	// and appends an integrity HMAC.
	_, encData, err := encType.EncryptMessage(s.subkey.KeyValue, plain, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL encrypt: %w", err)
	}

	// Wire token: [header][encrypted data]
	// The header on the wire uses EC=0, RRC=0 (matching what was encrypted).
	wire := make([]byte, krbgssapi.HdrLen+len(encData))
	copy(wire, header)
	copy(wire[krbgssapi.HdrLen:], encData)
	return wire, nil
}

// Read serves unwrapped plaintext to the caller. Internally it reads complete
// Kerberos GSSAPI SASL frames, verifies/decrypts them, and buffers the plaintext.
func (s *krbSASLConn) Read(p []byte) (int, error) {
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
	if msgLen < krbgssapi.HdrLen {
		return 0, fmt.Errorf("ldap: SASL frame too small (%d bytes)", msgLen)
	}

	raw := make([]byte, msgLen)
	if _, err := io.ReadFull(s.conn, raw); err != nil {
		return 0, err
	}

	var plaintext []byte
	var err error

	if s.mode == SASLSecuritySeal {
		plaintext, err = s.unsealRead(raw)
	} else {
		plaintext, err = s.verifyRead(raw)
	}
	if err != nil {
		return 0, err
	}
	s.rSeqNum++

	s.rBuf.store(plaintext)
	n, _ := s.rBuf.serve(p)
	return n, nil
}

// verifyRead parses an integrity-only WrapToken and verifies its checksum.
func (s *krbSASLConn) verifyRead(raw []byte) ([]byte, error) {
	token, err := unmarshalKrbWrapToken(raw)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL unmarshal: %w", err)
	}

	if _, err := token.Verify(s.subkey, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL verify: %w", err)
	}
	return token.Payload, nil
}

// unsealRead parses a sealed WrapToken: un-rotates by RRC, decrypts, and
// strips the trailing filler + header copy to return the plaintext.
func (s *krbSASLConn) unsealRead(raw []byte) ([]byte, error) {
	if len(raw) < krbgssapi.HdrLen {
		return nil, fmt.Errorf("ldap: sealed frame too short")
	}

	// Verify Token ID.
	if raw[0] != 0x05 || raw[1] != 0x04 {
		return nil, fmt.Errorf("ldap: wrong Token ID: expected 0504, got %02x%02x", raw[0], raw[1])
	}
	if raw[3] != krbgssapi.FillerByte {
		return nil, fmt.Errorf("ldap: unexpected filler byte: %02x", raw[3])
	}

	ec := binary.BigEndian.Uint16(raw[4:6])
	rrc := binary.BigEndian.Uint16(raw[6:8])

	encType, err := crypto.GetEtype(s.subkey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL unseal: %w", err)
	}

	// Copy the encrypted data portion (after the 16-byte header).
	data := make([]byte, len(raw)-krbgssapi.HdrLen)
	copy(data, raw[krbgssapi.HdrLen:])

	// Un-rotate if RRC > 0. Right rotation moved the last RRC bytes to
	// the front; undo by moving the first RRC bytes to the end.
	if rrc > 0 && len(data) > 0 {
		r := int(rrc) % len(data)
		if r > 0 {
			tmp := make([]byte, len(data))
			copy(tmp, data[r:])
			copy(tmp[len(data)-r:], data[:r])
			data = tmp
		}
	}

	// Decrypt: EncryptMessage output is [ciphertext(with confounder)][HMAC].
	// DecryptMessage strips the HMAC, decrypts, verifies integrity, and
	// removes the confounder, returning: plaintext_data || filler || header_copy.
	plain, err := encType.DecryptMessage(s.subkey.KeyValue, data, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf("ldap: kerberos SASL decrypt: %w", err)
	}

	// Strip trailing header_copy (16 bytes) and filler (EC bytes).
	trailerLen := int(ec) + krbgssapi.HdrLen
	if len(plain) < trailerLen {
		return nil, fmt.Errorf("ldap: decrypted payload too short: %d bytes, need %d trailer", len(plain), trailerLen)
	}
	return plain[:len(plain)-trailerLen], nil
}

// unmarshalKrbWrapToken parses an integrity-only GSS WrapToken from wire bytes,
// handling RRC (Right Rotation Count) un-rotation. The server may send tokens
// where the data portion (after the 16-byte header) has been right-rotated by
// RRC bytes.
//
// Wire format after rotation: [header(16)][rotated data...]
// After un-rotation the data is: [payload][checksum(EC bytes)]
func unmarshalKrbWrapToken(b []byte) (*krbgssapi.WrapToken, error) {
	if len(b) < krbgssapi.HdrLen {
		return nil, fmt.Errorf("bytes shorter than header length")
	}

	// Verify Token ID (0x0504).
	if b[0] != 0x05 || b[1] != 0x04 {
		return nil, fmt.Errorf("wrong Token ID: expected 0504, got %02x%02x", b[0], b[1])
	}

	flags := b[2]
	if b[3] != krbgssapi.FillerByte {
		return nil, fmt.Errorf("unexpected filler byte: expected 0xFF, got %02x", b[3])
	}

	ec := binary.BigEndian.Uint16(b[4:6])
	rrc := binary.BigEndian.Uint16(b[6:8])
	seqNum := binary.BigEndian.Uint64(b[8:16])

	data := make([]byte, len(b)-krbgssapi.HdrLen)
	copy(data, b[krbgssapi.HdrLen:])

	// Un-rotate data if RRC > 0.
	// Right rotation by RRC means the last RRC bytes were moved to the front.
	// To undo: move the first RRC bytes to the end.
	if rrc > 0 && len(data) > 0 {
		r := int(rrc) % len(data)
		if r > 0 {
			tmp := make([]byte, len(data))
			copy(tmp, data[r:])
			copy(tmp[len(data)-r:], data[:r])
			data = tmp
		}
	}

	// After un-rotation: [payload][checksum(EC bytes)]
	if int(ec) > len(data) {
		return nil, fmt.Errorf("EC (%d) exceeds data length (%d)", ec, len(data))
	}

	payloadEnd := len(data) - int(ec)
	payload := data[:payloadEnd]
	checksum := data[payloadEnd:]

	return &krbgssapi.WrapToken{
		Flags:     flags,
		EC:        ec,
		RRC:       rrc,
		SndSeqNum: seqNum,
		Payload:   payload,
		CheckSum:  checksum,
	}, nil
}

// Delegate remaining net.Conn methods to the underlying connection.
func (s *krbSASLConn) Close() error                       { return s.conn.Close() }
func (s *krbSASLConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *krbSASLConn) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *krbSASLConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *krbSASLConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *krbSASLConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
