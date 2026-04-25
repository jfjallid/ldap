package ldap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSASLReadBufferServeEmpty(t *testing.T) {
	var b saslReadBuffer
	out := make([]byte, 8)
	n, ok := b.serve(out)
	if ok || n != 0 {
		t.Fatalf("empty buffer: got n=%d ok=%v, want n=0 ok=false", n, ok)
	}
}

func TestSASLReadBufferStoreAndDrain(t *testing.T) {
	var b saslReadBuffer
	b.store([]byte("hello world"))

	out := make([]byte, 5)
	n, ok := b.serve(out)
	if !ok || n != 5 || string(out[:n]) != "hello" {
		t.Fatalf("first read: got n=%d ok=%v %q, want n=5 ok=true \"hello\"", n, ok, out[:n])
	}

	out = make([]byte, 100)
	n, ok = b.serve(out)
	if !ok || n != 6 || string(out[:n]) != " world" {
		t.Fatalf("second read: got n=%d ok=%v %q, want n=6 ok=true \" world\"", n, ok, out[:n])
	}

	n, ok = b.serve(out)
	if ok || n != 0 {
		t.Fatalf("drained read: got n=%d ok=%v, want n=0 ok=false", n, ok)
	}
}

func TestSASLReadBufferStoreResetsPosition(t *testing.T) {
	var b saslReadBuffer
	b.store([]byte("first"))

	half := make([]byte, 3)
	if n, _ := b.serve(half); n != 3 {
		t.Fatalf("partial drain: n=%d, want 3", n)
	}

	// New store must reset pos so the next serve reads from the start.
	b.store([]byte("second"))
	out := make([]byte, 6)
	n, ok := b.serve(out)
	if !ok || n != 6 || string(out[:n]) != "second" {
		t.Fatalf("post-store read: got n=%d ok=%v %q, want \"second\"", n, ok, out[:n])
	}
}

// fakeReadConn is a net.Conn whose Read returns from a fixed byte slice.
// Write/Close/deadline methods are stubs; only the reader is exercised by
// saslConn's frame-parsing path before Unseal would be called.
type fakeReadConn struct {
	r io.Reader
}

func (f *fakeReadConn) Read(p []byte) (int, error)       { return f.r.Read(p) }
func (f *fakeReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (f *fakeReadConn) Close() error                     { return nil }
func (f *fakeReadConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (f *fakeReadConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (f *fakeReadConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeReadConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeReadConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "fake" }
func (dummyAddr) String() string  { return "fake" }

// makeNTLMSaslConn returns a saslConn wrapping the given reader. session is
// nil because the tests below trigger error paths before Unseal is reached.
func makeNTLMSaslConn(r io.Reader) *saslConn {
	return &saslConn{conn: &fakeReadConn{r: r}}
}

func TestSASLConnReadHeaderEOF(t *testing.T) {
	c := makeNTLMSaslConn(bytes.NewReader(nil))
	out := make([]byte, 16)
	_, err := c.Read(out)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestSASLConnReadHeaderShort(t *testing.T) {
	// Only 2 of the 4 header bytes available before EOF.
	c := makeNTLMSaslConn(bytes.NewReader([]byte{0x00, 0x00}))
	out := make([]byte, 16)
	_, err := c.Read(out)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestSASLConnReadFrameTooLarge(t *testing.T) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, maxSASLPayload+1)
	c := makeNTLMSaslConn(bytes.NewReader(hdr))

	out := make([]byte, 16)
	_, err := c.Read(out)
	if err == nil {
		t.Fatal("expected error for oversize frame, got nil")
	}
	if !strings.Contains(err.Error(), "SASL frame too large") {
		t.Fatalf("expected 'SASL frame too large' error, got %v", err)
	}
}

func TestSASLConnReadBodyTruncated(t *testing.T) {
	// Header advertises 100 bytes but only 30 follow before EOF.
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 100)
	body := bytes.Repeat([]byte{0xAA}, 30)
	wire := append(hdr, body...)
	c := makeNTLMSaslConn(bytes.NewReader(wire))

	out := make([]byte, 200)
	_, err := c.Read(out)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}
