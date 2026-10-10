package ldap

import (
	"context"
	"errors"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// ErrAbandoned is returned by an operation whose request was abandoned, either
// through an explicit call to Conn.Abandon or because the context passed to a
// *WithContext variant was cancelled. Callers can test for it with errors.Is.
var ErrAbandoned = errors.New("ldap: request abandoned")

// Abandon sends an LDAP AbandonRequest (RFC 4511 §4.11) for messageID and
// unblocks whichever goroutine is waiting on that message, which returns
// ErrAbandoned.
//
// The abandon is advisory: the server is asked to stop processing the
// operation, but a server is free to finish it anyway. Either way nothing
// further is delivered to the waiting caller, because an AbandonRequest never
// draws a response and the message's response channel is closed here. The
// connection itself stays usable, unlike Close.
//
// Abandoning an unknown or already-completed message ID is a no-op.
func (l *Conn) Abandon(messageID int64) error {
	if l == nil || l.conn == nil {
		return ErrNilConnection
	}

	// The packet is built here rather than in processMessages because
	// nextMessageID reads from chanMessageID, which processMessages itself
	// feeds -- doing that from inside its select would deadlock.
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))
	// AbandonRequest ::= [APPLICATION 16] MessageID -- a primitive holding the
	// ID of the operation to abandon, not a constructed sequence.
	packet.AppendChild(ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, ApplicationAbandonRequest, messageID, "Abandon Request"))

	if l.Debug {
		l.Debug.PrintPacket(packet)
	}

	if !l.sendProcessMessage(&messagePacket{
		Op:        MessageCancel,
		MessageID: messageID,
		Packet:    packet,
	}) {
		return NewError(ErrorNetwork, errors.New("ldap: connection closed"))
	}
	return nil
}

// watchContext abandons msgCtx's request if ctx is cancelled before the request
// finishes. The watcher goroutine exits either way: finishMessage closes
// msgCtx.done, which is the second arm of the select.
//
// A nil context, or one that can never be cancelled (context.Background), skips
// the goroutine entirely so the uncancellable callers pay nothing.
func (l *Conn) watchContext(ctx context.Context, msgCtx *messageContext) {
	if ctx == nil || ctx.Done() == nil {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			// Best-effort: the request may have completed in the meantime, in
			// which case this is a no-op on an unknown message ID.
			_ = l.Abandon(msgCtx.id)
		case <-msgCtx.done:
		}
	}()
}

// AbandonAll abandons every request currently awaiting a response.
//
// It exists for callers that do not hold the message IDs themselves -- an
// interactive client, say, cancelling whatever the user's last command set in
// motion, without having to thread a context through every code path that might
// issue a request. Each waiter returns ErrAbandoned and the connection stays
// usable.
func (l *Conn) AbandonAll() error {
	if l == nil || l.conn == nil {
		return ErrNilConnection
	}
	l.messageMutex.Lock()
	ids := make([]int64, 0, len(l.inFlight))
	for id := range l.inFlight {
		ids = append(ids, id)
	}
	l.messageMutex.Unlock()

	// Abandon is called outside the lock: it allocates a message ID of its own,
	// which reads from a channel processMessages feeds.
	var firstErr error
	for _, id := range ids {
		if err := l.Abandon(id); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
