package gssapi

import (
	"fmt"

	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/jfjallid/gokrb5/v9/gssapi"
	"github.com/jfjallid/gokrb5/v9/messages"
)

// TokenId values for the KRB5 GSS-API mechanism token (RFC 4121 §4.1).
const (
	tokenIdKrb5APReq uint16 = 1
	tokenIdKrb5APRep uint16 = 2
	tokenIdKrb5Error uint16 = 3
)

// krb5Token is the GSS-API Kerberos 5 mechanism token: the mechanism OID and a
// 2-byte token id followed by the wrapped AP-REQ / AP-REP / KRB-ERROR, all
// inside an application-tagged (tag 0) ASN.1 wrapper. See RFC 4121 §4.1.
//
// This type is owned by the ldap gssapi package so that the package depends only
// on gokrb5.
type krb5Token struct {
	Oid      asn1.ObjectIdentifier
	TokenId  uint16
	APReq    messages.APReq
	APRep    messages.APRep
	KRBError messages.KRBError
}

// Marshal serialises the token. Only the AP-REQ token id is produced by the
// client side; AP-REP and KRB-ERROR are receive-only.
func (t *krb5Token) Marshal() ([]byte, error) {
	res, err := asn1.Marshal(t.Oid)
	if err != nil {
		return nil, err
	}
	res = le.AppendUint16(res, t.TokenId)

	switch t.TokenId {
	case tokenIdKrb5APReq:
		buf, err := t.APReq.Marshal()
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	default:
		return nil, fmt.Errorf("marshal of KRB5Token id %d not implemented", t.TokenId)
	}

	r := asn1.RawValue{
		Class:      asn1.ClassApplication,
		IsCompound: true,
		Tag:        0,
		Bytes:      res,
	}
	return asn1.Marshal(r)
}

// Unmarshal parses an AP-REP or KRB-ERROR mechanism token received from the
// server.
func (t *krb5Token) Unmarshal(buf []byte) error {
	rest, err := asn1.UnmarshalWithParams(buf, &t.Oid, "application,explicit,tag:0")
	if err != nil {
		return fmt.Errorf("failed to unmarshal KRB5Token OID: %w", err)
	}
	if !t.Oid.Equal(gssapi.OIDKRB5.OID()) {
		return fmt.Errorf("KRB5Token OID is %s, expected %s", t.Oid.String(), gssapi.OIDKRB5.OID().String())
	}
	if len(rest) < 2 {
		return fmt.Errorf("buffer too short for KRB5Token")
	}

	t.TokenId = le.Uint16(rest[0:2])
	switch t.TokenId {
	case tokenIdKrb5APRep:
		rep := messages.APRep{}
		if err = rep.Unmarshal(rest[2:]); err != nil {
			return err
		}
		t.APRep = rep
	case tokenIdKrb5Error:
		krb5err := messages.KRBError{}
		if err = krb5err.Unmarshal(rest[2:]); err != nil {
			return err
		}
		t.KRBError = krb5err
	default:
		return fmt.Errorf("unmarshal of KRB5Token id %d not implemented", t.TokenId)
	}
	return nil
}
