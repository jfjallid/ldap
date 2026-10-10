//go:build windows
// +build windows

package gssapi

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
)

// SSPIClient implements ldap.GSSAPIClient interface.
// Depends on secur32.dll.
type SSPIClient struct {
	creds           *sspi.Credentials
	ctx             *kerberos.ClientContext
	channelBindings []byte
	// saslSecurity is the RFC 4752 security layer to select in
	// NegotiateSaslAuth (0 none, 2 integrity, 4 confidentiality), set by
	// ldap through SetSASLSecurity.
	saslSecurity int
}

// kerbWrapNoEncrypt is KERB_WRAP_NO_ENCRYPT (SECQOP_WRAP_NO_ENCRYPT): passed to
// EncryptMessage it makes Wrap sign without encrypting, and DecryptMessage
// reports it for a message that was only signed.
const kerbWrapNoEncrypt = 0x80000001

// saslMaxReceive is the maximum wrapped message size advertised to the server
// when a security layer is selected, matching the gokrb5 client.
const saslMaxReceive = 0xFFFF

// SetSASLSecurity sets the security layer NegotiateSaslAuth selects. ldap calls
// it before the bind with the requested SASLSecurityMode.
func (c *SSPIClient) SetSASLSecurity(mode int) {
	c.saslSecurity = mode
}

// NewSSPIClient returns a client with credentials of the current user.
func NewSSPIClient() (*SSPIClient, error) {
	creds, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}

	return NewSSPIClientWithCredentials(creds), nil
}

// NewSSPIClientWithCredentials returns a client with the provided credentials.
func NewSSPIClientWithCredentials(creds *sspi.Credentials) *SSPIClient {
	return &SSPIClient{
		creds: creds,
	}
}

// NewSSPIClientWithUserCredentials returns a client using the provided user's
// credentials.
func NewSSPIClientWithUserCredentials(domain, username, password string) (*SSPIClient, error) {
	creds, err := kerberos.AcquireUserCredentials(domain, username, password)
	if err != nil {
		return nil, err
	}

	return &SSPIClient{
		creds: creds,
	}, nil
}

// NewSSPIClientWithChannelBinding creates an RFC 5929 compliant client.
func NewSSPIClientWithChannelBinding(cert *x509.Certificate) (*SSPIClient, error) {
	creds, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}

	certHash := calculateCertificateHash(cert)
	if certHash == nil {
		return nil, fmt.Errorf("failed to calculate certificate hash")
	}

	tlsChannelBinding := append([]byte("tls-server-end-point:"), certHash...)

	return &SSPIClient{
		creds:           creds,
		channelBindings: createChannelBindingsStructure(tlsChannelBinding),
	}, nil
}

// Close deletes any established secure context and closes the client.
func (c *SSPIClient) Close() error {
	err1 := c.DeleteSecContext()
	err2 := c.creds.Release()
	c.creds = nil
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return nil
}

// DeleteSecContext destroys any established secure context, unless
// SASLWrapSession has handed it to a wrapping session.
func (c *SSPIClient) DeleteSecContext() error {
	err := c.ctx.Release()
	c.ctx = nil
	return err
}

// InitSecContext initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (c *SSPIClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, token, []int{})
}

// InitSecContextWithOptions initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (c *SSPIClient) InitSecContextWithOptions(target string, token []byte, APOptions []int) ([]byte, bool, error) {
	sspiFlags := uint32(sspi.ISC_REQ_INTEGRITY | sspi.ISC_REQ_CONFIDENTIALITY | sspi.ISC_REQ_MUTUAL_AUTH)

	switch token {
	case nil:
		// Use channel bindings if available, otherwise fall back to the standard method.
		var ctx *kerberos.ClientContext
		var completed bool
		var output []byte
		var err error

		if len(c.channelBindings) > 0 {
			ctx, completed, output, err = kerberos.NewClientContextWithChannelBindings(c.creds, target, sspiFlags, c.channelBindings)
		} else {
			ctx, completed, output, err = kerberos.NewClientContextWithFlags(c.creds, target, sspiFlags)
		}

		if err != nil {
			return nil, false, err
		}
		c.ctx = ctx

		return output, !completed, nil
	default:
		completed, output, err := c.ctx.Update(token)
		if err != nil {
			return nil, false, err
		}
		if err := c.ctx.VerifyFlags(); err != nil {
			return nil, false, fmt.Errorf("error verifying flags: %v", err)
		}
		return output, !completed, nil
	}
}

// NegotiateSaslAuth performs the last step of the SASL handshake.
// See RFC 4752 section 3.1.
func (c *SSPIClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	// Using SSPI rather than of GSSAPI, relevant documentation of differences here:
	// https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi

	// KERB_WRAP_NO_ENCRYPT (SECQOP_WRAP_NO_ENCRYPT) flag indicates Wrap and Unwrap
	// should only sign & verify (not encrypt & decrypt).
	const KERB_WRAP_NO_ENCRYPT = 0x80000001

	// https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-decryptmessage
	flags, inputPayload, err := c.ctx.DecryptMessage(token, 0)
	if err != nil {
		return nil, fmt.Errorf("error decrypting message: %w", err)
	}
	if flags&KERB_WRAP_NO_ENCRYPT == 0 {
		// Encrypted message, this is unexpected.
		return nil, fmt.Errorf("message encrypted")
	}

	// `bytes` describes available security context:
	// 		"the first octet of resulting cleartext as a
	// 		bit-mask specifying the security layers supported by the server and
	// 		the second through fourth octets as the maximum size output_message
	// 		the server is able to receive (in network byte order).  If the
	// 		resulting cleartext is not 4 octets long, the client fails the
	// 		negotiation.  The client verifies that the server maximum buffer is 0
	// 		if the server does not advertise support for any security layer."
	// From https://www.rfc-editor.org/rfc/rfc4752#section-3.1
	if len(inputPayload) != 4 {
		return nil, fmt.Errorf("bad server token")
	}
	if inputPayload[0] == 0x0 && !bytes.Equal(inputPayload, []byte{0x0, 0x0, 0x0, 0x0}) {
		return nil, fmt.Errorf("bad server token")
	}

	// Security layers https://www.rfc-editor.org/rfc/rfc4422#section-3.7
	// https://www.rfc-editor.org/rfc/rfc4752#section-3.3
	// supportNoSecurity := input[0] & 0b00000001
	// supportIntegrity := input[0] & 0b00000010
	// supportPrivacy := input[0] & 0b00000100
	selectedSec := c.saslSecurity
	var maxSecMsgSize uint32
	if selectedSec != 0 {
		if inputPayload[0]&byte(selectedSec) == 0 {
			return nil, fmt.Errorf("server does not offer SASL security layer %d (offered %#x)", selectedSec, inputPayload[0])
		}
		maxSecMsgSize = saslMaxReceive
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-encryptmessage
	inputPayload, err = c.ctx.EncryptMessage(handshakePayload(byte(selectedSec), maxSecMsgSize, []byte(authzid)), KERB_WRAP_NO_ENCRYPT, 0)
	if err != nil {
		return nil, fmt.Errorf("error encrypting message: %w", err)
	}

	return inputPayload, nil
}

func handshakePayload(secLayer byte, maxSize uint32, authzid []byte) []byte {
	// construct payload and send unencrypted:
	// 		"The client then constructs data, with the first octet containing the
	// 		bit-mask specifying the selected security layer, the second through
	// 		fourth octets containing in network byte order the maximum size
	// 		output_message the client is able to receive (which MUST be 0 if the
	// 		client does not support any security layer), and the remaining octets
	// 		containing the UTF-8 [UTF8] encoded authorization identity.
	// 		(Implementation note: The authorization identity is not terminated
	// 		with the zero-valued (%x00) octet (e.g., the UTF-8 encoding of the
	// 		NUL (U+0000) character)).  The client passes the data to GSS_Wrap
	// 		with conf_flag set to FALSE and responds with the generated
	// 		output_message.  The client can then consider the server
	// 		authenticated."
	// From https://www.rfc-editor.org/rfc/rfc4752#section-3.1

	// Client picks security layer to use, 0 is disabled.
	var selectedSecurity byte = secLayer
	var truncatedSize uint32 // must be 0 if secLayer is 0
	if selectedSecurity != 0 {
		// Only 3 bytes to describe the max size, set the maximum.
		truncatedSize = 0b00000000_11111111_11111111_11111111
		if truncatedSize > maxSize {
			truncatedSize = maxSize
		}
	}

	payload := make([]byte, 4, 4+len(authzid))
	binary.BigEndian.PutUint32(payload, truncatedSize)
	payload[0] = selectedSecurity // Overwrites most significant byte of `maxSize`
	payload = append(payload, []byte(authzid)...)

	return payload
}

// createChannelBindingsStructure creates a Windows SEC_CHANNEL_BINDINGS structure.
// This is the format that Windows SSPI expects for channel binding tokens.
// https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_channel_bindings
func createChannelBindingsStructure(applicationData []byte) []byte {
	const headerSize = 32 // 8 DWORDs * 4 bytes each
	appDataLen := uint32(len(applicationData))
	appDataOffset := uint32(headerSize)

	buf := make([]byte, headerSize+len(applicationData))

	// All initiator and acceptor fields are 0 for TLS channel binding.
	binary.LittleEndian.PutUint32(buf[24:], appDataLen)    // cbApplicationDataLength
	binary.LittleEndian.PutUint32(buf[28:], appDataOffset) // dwApplicationDataOffset

	copy(buf[headerSize:], applicationData)

	return buf
}

// SASLWrapSession returns the RFC 4752 security layer selected in
// NegotiateSaslAuth, or nil when none was. ldap wraps every message after the
// bind through it. The session takes over the context and credential handles,
// because ldap deletes the client's context when the bind returns; the session
// releases them when ldap closes the connection.
func (c *SSPIClient) SASLWrapSession() SASLWrapper {
	if c.saslSecurity == 0 || c.ctx == nil {
		return nil
	}
	session := &sspiWrapSession{ctx: c.ctx, creds: c.creds, seal: c.saslSecurity == 4}
	c.ctx, c.creds = nil, nil
	return session
}

// sspiWrapSession wraps LDAP messages with SSPI's EncryptMessage and
// DecryptMessage over the established Kerberos context. The wrapped bytes are
// the GSS-API Wrap token (the token, data and padding buffers concatenated, see
// https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi).
// SSPI keeps the per-direction sequence numbers, so ldap's seqNum is only
// returned incremented.
type sspiWrapSession struct {
	mu    sync.Mutex // SSPI per-message calls on one context are not documented as thread-safe
	ctx   *kerberos.ClientContext
	creds *sspi.Credentials
	seal  bool // confidentiality; otherwise integrity only
}

func (s *sspiWrapSession) Seal(dst, plaintext []byte, seqNum uint32) ([]byte, uint32) {
	out, next, _ := s.SealErr(dst, plaintext, seqNum)
	return out, next
}

func (s *sspiWrapSession) SealErr(dst, plaintext []byte, seqNum uint32) ([]byte, uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return dst, seqNum + 1, fmt.Errorf("sspi: wrap after the session was closed")
	}
	var qop uint32
	if !s.seal {
		qop = kerbWrapNoEncrypt
	}
	// EncryptMessage works in place, so give it a copy.
	msg := append([]byte(nil), plaintext...)
	wrapped, err := s.ctx.EncryptMessage(msg, qop, 0)
	if err != nil {
		return dst, seqNum + 1, fmt.Errorf("sspi: EncryptMessage: %w", err)
	}
	return append(dst, wrapped...), seqNum + 1, nil
}

func (s *sspiWrapSession) Unseal(dst, wrapped []byte, seqNum uint32) ([]byte, uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return nil, 0, fmt.Errorf("sspi: unwrap after the session was closed")
	}
	qop, data, err := s.ctx.DecryptMessage(append([]byte(nil), wrapped...), 0)
	if err != nil {
		return nil, 0, fmt.Errorf("sspi: DecryptMessage: %w", err)
	}
	if s.seal && qop&kerbWrapNoEncrypt != 0 {
		return nil, 0, fmt.Errorf("sspi: server sent an unencrypted message on a sealed connection")
	}
	return append(dst, data...), seqNum + 1, nil
}

// Close releases the context and credential handles taken from the client.
func (s *sspiWrapSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.ctx.Release()
	s.ctx = nil
	if cerr := s.creds.Release(); err == nil {
		err = cerr
	}
	s.creds = nil
	return err
}
