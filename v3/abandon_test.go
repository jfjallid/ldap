package ldap

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// silentServer accepts one connection and reads LDAP packets from it without
// ever replying, so a request sent to it stays in flight until the client
// abandons it. Every packet it receives is published on packets.
type silentServer struct {
	addr    string
	packets chan *ber.Packet
	close   func()
}

func newSilentServer(t *testing.T) *silentServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &silentServer{
		addr:    ln.Addr().String(),
		packets: make(chan *ber.Packet, 8),
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			packet, err := ber.ReadPacket(conn)
			if err != nil {
				return
			}
			s.packets <- packet
		}
	}()
	s.close = func() { ln.Close() }
	return s
}

func (s *silentServer) nextPacket(t *testing.T) *ber.Packet {
	t.Helper()
	select {
	case p := <-s.packets:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a packet to reach the server")
		return nil
	}
}

// messageID returns the MessageID field of a request packet.
func messageIDOf(t *testing.T, packet *ber.Packet) int64 {
	t.Helper()
	if len(packet.Children) < 1 {
		t.Fatalf("packet has no MessageID child")
	}
	id, ok := packet.Children[0].Value.(int64)
	if !ok {
		t.Fatalf("MessageID is %T, want int64", packet.Children[0].Value)
	}
	return id
}

// A search against a server that never answers must return once its context is
// cancelled, rather than blocking forever, and must tell the server to stop
// working via an AbandonRequest.
func TestSearchWithContextAbandonsInFlightRequest(t *testing.T) {
	srv := newSilentServer(t)
	defer srv.close()

	c, err := net.Dial("tcp", srv.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := NewConn(c, false)
	conn.Start()
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type searchResult struct {
		res *SearchResult
		err error
	}
	done := make(chan searchResult, 1)
	go func() {
		res, err := conn.SearchWithContext(ctx, NewSearchRequest(
			"dc=example,dc=com", ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", nil, nil,
		))
		done <- searchResult{res, err}
	}()

	// Only cancel once the search is genuinely in flight, otherwise the test
	// could pass without ever exercising the abandon path.
	searchPacket := srv.nextPacket(t)
	searchID := messageIDOf(t, searchPacket)
	cancel()

	select {
	case got := <-done:
		if !errors.Is(got.err, ErrAbandoned) {
			t.Fatalf("search error = %v; want ErrAbandoned", got.err)
		}
		if got.res == nil {
			t.Error("want the entries received so far, got a nil result")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling the context did not unblock the search")
	}

	abandonPacket := srv.nextPacket(t)
	if len(abandonPacket.Children) < 2 {
		t.Fatalf("abandon packet has %d children, want 2", len(abandonPacket.Children))
	}
	if tag := abandonPacket.Children[1].Tag; tag != ApplicationAbandonRequest {
		t.Errorf("second packet tag = %d; want ApplicationAbandonRequest (%d)", tag, ApplicationAbandonRequest)
	}
	// The abandon names the search's message ID, and carries a new one of its
	// own. The body is read from the raw content octets: a generic BER decode
	// leaves Value nil for an application-class primitive, which is why the
	// library runs addRequestDescriptions over incoming requests.
	target, err := ber.ParseInt64(abandonPacket.Children[1].Data.Bytes())
	if err != nil {
		t.Fatalf("decoding the abandoned message ID: %v", err)
	}
	if target != searchID {
		t.Errorf("abandon targets message %d; want the search's ID %d", target, searchID)
	}
	if got := messageIDOf(t, abandonPacket); got == searchID {
		t.Errorf("abandon reused message ID %d; it must carry its own", got)
	}

	// The whole point of abandoning rather than closing: the connection lives.
	if conn.IsClosing() {
		t.Error("connection is closing after an abandon; it should stay usable")
	}
}

// Abandoning a message that already finished (or never existed) is a no-op
// rather than an error or a panic, since the race is unavoidable for a caller.
func TestAbandonUnknownMessageIsNoOp(t *testing.T) {
	srv := newSilentServer(t)
	defer srv.close()

	c, err := net.Dial("tcp", srv.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := NewConn(c, false)
	conn.Start()
	defer conn.Close()

	if err := conn.Abandon(99999); err != nil {
		t.Fatalf("Abandon on an unknown message ID = %v; want nil", err)
	}
	if conn.IsClosing() {
		t.Error("connection is closing after abandoning an unknown message")
	}
}

// An uncancellable context must not leave a watcher goroutine behind, and must
// not interfere with a request that completes normally.
func TestSearchWithBackgroundContextSkipsWatcher(t *testing.T) {
	srv := newSilentServer(t)
	defer srv.close()

	c, err := net.Dial("tcp", srv.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := NewConn(c, false)
	conn.SetTimeout(200 * time.Millisecond)
	conn.Start()
	defer conn.Close()

	_, err = conn.SearchWithContext(context.Background(), NewSearchRequest(
		"dc=example,dc=com", ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil,
	))
	if err == nil {
		t.Fatal("want a timeout error from the silent server, got nil")
	}
	if errors.Is(err, ErrAbandoned) {
		t.Errorf("error = %v; an uncancellable context must not abandon", err)
	}
}

// AbandonAll is the entry point for callers that never see a message ID, such
// as an interactive client cancelling whatever the last command started.
func TestAbandonAllCancelsInFlightRequest(t *testing.T) {
	srv := newSilentServer(t)
	defer srv.close()

	c, err := net.Dial("tcp", srv.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := NewConn(c, false)
	conn.Start()
	defer conn.Close()

	done := make(chan error, 1)
	go func() {
		_, err := conn.Search(NewSearchRequest(
			"dc=example,dc=com", ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", nil, nil,
		))
		done <- err
	}()

	searchID := messageIDOf(t, srv.nextPacket(t))
	if err := conn.AbandonAll(); err != nil {
		t.Fatalf("AbandonAll: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, ErrAbandoned) {
			t.Fatalf("search error = %v; want ErrAbandoned", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AbandonAll did not unblock the search")
	}

	abandon := srv.nextPacket(t)
	target, err := ber.ParseInt64(abandon.Children[1].Data.Bytes())
	if err != nil {
		t.Fatalf("decoding the abandoned message ID: %v", err)
	}
	if target != searchID {
		t.Errorf("abandon targets message %d; want %d", target, searchID)
	}
	if conn.IsClosing() {
		t.Error("connection is closing after AbandonAll")
	}
}

// With nothing outstanding there is nothing to abandon, and in particular no
// stale ID left behind by a request that already completed.
func TestAbandonAllWithNothingInFlight(t *testing.T) {
	srv := newSilentServer(t)
	defer srv.close()

	c, err := net.Dial("tcp", srv.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := NewConn(c, false)
	conn.SetTimeout(200 * time.Millisecond)
	conn.Start()
	defer conn.Close()

	// Run a request to completion (by timeout) so its ID has been added and
	// then removed again.
	_, _ = conn.Search(NewSearchRequest(
		"dc=example,dc=com", ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil,
	))

	conn.messageMutex.Lock()
	n := len(conn.inFlight)
	conn.messageMutex.Unlock()
	if n != 0 {
		t.Errorf("%d message(s) still tracked as in flight after completion", n)
	}
	if err := conn.AbandonAll(); err != nil {
		t.Errorf("AbandonAll with nothing outstanding = %v; want nil", err)
	}
}
