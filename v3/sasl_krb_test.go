package ldap

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/jfjallid/gokrb5/v8/crypto"
	krbgssapi "github.com/jfjallid/gokrb5/v8/gssapi"
	"github.com/jfjallid/gokrb5/v8/iana/etypeID"
	"github.com/jfjallid/gokrb5/v8/iana/keyusage"
	"github.com/jfjallid/gokrb5/v8/types"
)

func newTestSubkey(t *testing.T) (keyType int32, keyValue []byte) {
	t.Helper()
	keyType = etypeID.AES128_CTS_HMAC_SHA1_96
	encType, err := crypto.GetEtype(keyType)
	if err != nil {
		t.Fatalf("GetEtype: %v", err)
	}
	keyValue = make([]byte, encType.GetKeyByteSize())
	if _, err := rand.Read(keyValue); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return keyType, keyValue
}

// peerSealWrite mirrors krbSASLConn.sealWrite but uses GSSAPI_ACCEPTOR_SEAL,
// emulating what the server writes back to the client.
func peerSealWrite(subkey types.EncryptionKey, plaintext []byte, seqNum uint64) ([]byte, error) {
	encType, err := crypto.GetEtype(subkey.KeyType)
	if err != nil {
		return nil, err
	}

	flags := krbgssapi.MICTokenFlagAcceptorSubkey | krbgssapi.MICTokenFlagSealed | krbgssapi.MICTokenFlagSentByAcceptor
	header := make([]byte, krbgssapi.HdrLen)
	header[0] = 0x05
	header[1] = 0x04
	header[2] = byte(flags)
	header[3] = krbgssapi.FillerByte
	binary.BigEndian.PutUint64(header[8:16], seqNum)

	plain := make([]byte, len(plaintext)+krbgssapi.HdrLen)
	copy(plain, plaintext)
	copy(plain[len(plaintext):], header)

	_, encData, err := encType.EncryptMessage(subkey.KeyValue, plain, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, err
	}

	wire := make([]byte, krbgssapi.HdrLen+len(encData))
	copy(wire, header)
	copy(wire[krbgssapi.HdrLen:], encData)
	return wire, nil
}

// peerSignWrite mirrors krbSASLConn.signWrite using GSSAPI_ACCEPTOR_SEAL.
func peerSignWrite(subkey types.EncryptionKey, plaintext []byte, seqNum uint64) ([]byte, error) {
	encType, err := crypto.GetEtype(subkey.KeyType)
	if err != nil {
		return nil, err
	}
	token := &krbgssapi.WrapToken{
		Flags:     krbgssapi.MICTokenFlagAcceptorSubkey | krbgssapi.MICTokenFlagSentByAcceptor,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: seqNum,
		Payload:   plaintext,
	}
	// Acceptor signs outgoing tokens with GSSAPI_ACCEPTOR_SEAL; the
	// initiator's krbSASLConn.Read verifies with the same keyusage.
	if err := token.SetCheckSum(subkey, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, err
	}
	return token.Marshal()
}

// frameWith4ByteLen prepends the 4-byte big-endian length prefix used by
// SASL framing.
func frameWith4ByteLen(p []byte) []byte {
	frame := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(p)))
	copy(frame[4:], p)
	return frame
}

// readClientFrame reads a single SASL frame from r and returns the wrapped
// body (without the length prefix).
func readClientFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("read frame body: %v", err)
	}
	return body
}

func TestKrbSASLConnWriteSeal(t *testing.T) {
	keyType, keyValue := newTestSubkey(t)

	clientSide, peerSide := net.Pipe()
	defer clientSide.Close()
	defer peerSide.Close()

	c := newKrbSASLConn(clientSide, keyType, keyValue, SASLSecuritySeal)

	payload := []byte("hello kerberos seal")
	expectedSeq := c.wSeqNum
	done := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		done <- err
	}()

	wire := readClientFrame(t, peerSide)
	if err := <-done; err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Decrypt the wire bytes as the peer (server) would.
	if len(wire) < krbgssapi.HdrLen {
		t.Fatalf("wire too short: %d bytes", len(wire))
	}
	if wire[0] != 0x05 || wire[1] != 0x04 {
		t.Fatalf("token id: got %02x%02x", wire[0], wire[1])
	}
	gotSeq := binary.BigEndian.Uint64(wire[8:16])
	if gotSeq != expectedSeq {
		t.Fatalf("SndSeqNum: got %d, want %d", gotSeq, expectedSeq)
	}

	encType, _ := crypto.GetEtype(keyType)
	plain, err := encType.DecryptMessage(keyValue, wire[krbgssapi.HdrLen:], keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		t.Fatalf("peer DecryptMessage: %v", err)
	}
	if len(plain) < krbgssapi.HdrLen {
		t.Fatalf("decrypted plain too short: %d", len(plain))
	}
	got := plain[:len(plain)-krbgssapi.HdrLen]
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", got, payload)
	}
}

func TestKrbSASLConnWriteSign(t *testing.T) {
	keyType, keyValue := newTestSubkey(t)
	subkey := types.EncryptionKey{KeyType: keyType, KeyValue: keyValue}

	clientSide, peerSide := net.Pipe()
	defer clientSide.Close()
	defer peerSide.Close()

	c := newKrbSASLConn(clientSide, keyType, keyValue, SASLSecuritySign)

	payload := []byte("hello kerberos sign")
	done := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		done <- err
	}()

	wire := readClientFrame(t, peerSide)
	if err := <-done; err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Parse and verify as the peer (acceptor) — initiator-seal keyusage is
	// what the client signed with.
	var token krbgssapi.WrapToken
	if err := token.Unmarshal(wire, false); err != nil {
		t.Fatalf("WrapToken.Unmarshal: %v", err)
	}
	ok, err := token.Verify(subkey, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil || !ok {
		t.Fatalf("Verify: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(token.Payload, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", token.Payload, payload)
	}
}

func TestKrbSASLConnReadSeal(t *testing.T) {
	keyType, keyValue := newTestSubkey(t)
	subkey := types.EncryptionKey{KeyType: keyType, KeyValue: keyValue}

	clientSide, peerSide := net.Pipe()
	defer clientSide.Close()
	defer peerSide.Close()

	c := newKrbSASLConn(clientSide, keyType, keyValue, SASLSecuritySeal)

	payload := []byte("server response seal")
	wire, err := peerSealWrite(subkey, payload, c.rSeqNum)
	if err != nil {
		t.Fatalf("peerSealWrite: %v", err)
	}

	go func() {
		_, _ = peerSide.Write(frameWith4ByteLen(wire))
	}()

	out := make([]byte, len(payload))
	if _, err := io.ReadFull(c, out); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", out, payload)
	}
}

func TestKrbSASLConnReadSign(t *testing.T) {
	keyType, keyValue := newTestSubkey(t)
	subkey := types.EncryptionKey{KeyType: keyType, KeyValue: keyValue}

	clientSide, peerSide := net.Pipe()
	defer clientSide.Close()
	defer peerSide.Close()

	c := newKrbSASLConn(clientSide, keyType, keyValue, SASLSecuritySign)

	payload := []byte("server response sign")
	wire, err := peerSignWrite(subkey, payload, c.rSeqNum)
	if err != nil {
		t.Fatalf("peerSignWrite: %v", err)
	}

	go func() {
		_, _ = peerSide.Write(frameWith4ByteLen(wire))
	}()

	out := make([]byte, len(payload))
	if _, err := io.ReadFull(c, out); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", out, payload)
	}
}

func TestKrbUnmarshalRRCRoundTrip(t *testing.T) {
	// Hand-build a sign token with non-zero RRC. The token's wire form has
	// the data portion right-rotated by RRC bytes. unmarshalKrbWrapToken
	// must un-rotate before exposing the payload+checksum.
	keyType, keyValue := newTestSubkey(t)
	subkey := types.EncryptionKey{KeyType: keyType, KeyValue: keyValue}

	encType, _ := crypto.GetEtype(keyType)
	payload := []byte("rrc-test-payload")
	token := &krbgssapi.WrapToken{
		Flags:     krbgssapi.MICTokenFlagAcceptorSubkey,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 42,
		Payload:   payload,
	}
	if err := token.SetCheckSum(subkey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		t.Fatalf("SetCheckSum: %v", err)
	}
	wire, err := token.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Right-rotate the data portion by RRC=3 bytes.
	const rrc = 3
	header := wire[:krbgssapi.HdrLen]
	data := wire[krbgssapi.HdrLen:]
	if len(data) <= rrc {
		t.Fatalf("data too short for rotation: %d bytes", len(data))
	}
	rotated := make([]byte, len(data))
	copy(rotated, data[len(data)-rrc:])
	copy(rotated[rrc:], data[:len(data)-rrc])

	// Patch the RRC field in the header.
	patched := make([]byte, len(wire))
	copy(patched, header)
	binary.BigEndian.PutUint16(patched[6:8], rrc)
	copy(patched[krbgssapi.HdrLen:], rotated)

	got, err := unmarshalKrbWrapToken(patched)
	if err != nil {
		t.Fatalf("unmarshalKrbWrapToken: %v", err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", got.Payload, payload)
	}
	if got.SndSeqNum != 42 {
		t.Fatalf("SndSeqNum: got %d, want 42", got.SndSeqNum)
	}
}

func TestKrbSASLConnReadFrameTooLarge(t *testing.T) {
	keyType, keyValue := newTestSubkey(t)
	c := newKrbSASLConn(&fakeReadConn{r: bytes.NewReader(headerOf(maxSASLPayload + 1))}, keyType, keyValue, SASLSecuritySeal)

	out := make([]byte, 16)
	_, err := c.Read(out)
	if err == nil || !strings.Contains(err.Error(), "SASL frame too large") {
		t.Fatalf("expected 'SASL frame too large' error, got %v", err)
	}
}

func TestKrbSASLConnReadFrameTooSmall(t *testing.T) {
	keyType, keyValue := newTestSubkey(t)
	// msgLen is below krbgssapi.HdrLen → triggers "too small" error path.
	c := newKrbSASLConn(&fakeReadConn{r: bytes.NewReader(headerOf(uint32(krbgssapi.HdrLen - 1)))}, keyType, keyValue, SASLSecuritySeal)

	out := make([]byte, 16)
	_, err := c.Read(out)
	if err == nil || !strings.Contains(err.Error(), "SASL frame too small") {
		t.Fatalf("expected 'SASL frame too small' error, got %v", err)
	}
}

func TestKrbSASLConnReadHeaderEOF(t *testing.T) {
	keyType, keyValue := newTestSubkey(t)
	c := newKrbSASLConn(&fakeReadConn{r: bytes.NewReader(nil)}, keyType, keyValue, SASLSecuritySign)

	out := make([]byte, 16)
	_, err := c.Read(out)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

// headerOf returns a 4-byte big-endian length prefix.
func headerOf(n uint32) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, n)
	return hdr
}
