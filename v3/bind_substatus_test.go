package ldap

import (
	"errors"
	"fmt"
	"testing"
)

func TestExtractBindSubStatus(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantOK   bool
		wantCode uint32
	}{
		{
			name: "channel binding required",
			err: &Error{
				ResultCode: LDAPResultInvalidCredentials,
				Err:        errors.New("80090346: LdapErr: DSID-0C09075C, comment: AcceptSecurityContext error, data 80090346, v4563"),
			},
			wantOK:   true,
			wantCode: SubStatusBadBindings,
		},
		{
			name: "wrong password",
			err: &Error{
				ResultCode: LDAPResultInvalidCredentials,
				Err:        errors.New("80090308: LdapErr: DSID-0C09075C, comment: AcceptSecurityContext error, data 52e, v4563"),
			},
			wantOK:   true,
			wantCode: SubStatusInvalidCredentials,
		},
		{
			name: "account locked",
			err: &Error{
				ResultCode: LDAPResultInvalidCredentials,
				Err:        errors.New("comment: AcceptSecurityContext error, data 775, v4563"),
			},
			wantOK:   true,
			wantCode: SubStatusAccountLocked,
		},
		{
			name:   "wrapped error preserves substatus extraction",
			err:    fmt.Errorf("bind: %w", &Error{ResultCode: LDAPResultInvalidCredentials, Err: errors.New("data 80090346, v4563")}),
			wantOK: true, wantCode: SubStatusBadBindings,
		},
		{
			name:   "non-AD diagnostic message",
			err:    &Error{ResultCode: LDAPResultInvalidCredentials, Err: errors.New("invalid credentials")},
			wantOK: false,
		},
		{
			name:   "nil error",
			err:    nil,
			wantOK: false,
		},
		{
			name:   "non-ldap error",
			err:    errors.New("some random error with data 80090346 in it"),
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotCode, gotOK := ExtractBindSubStatus(tc.err)
			if gotOK != tc.wantOK {
				t.Fatalf("ok = %v, want %v (err=%v)", gotOK, tc.wantOK, tc.err)
			}
			if gotOK && gotCode != tc.wantCode {
				t.Fatalf("code = 0x%x, want 0x%x", gotCode, tc.wantCode)
			}
		})
	}
}

func TestIsChannelBindingRequired(t *testing.T) {
	cbErr := &Error{
		ResultCode: LDAPResultInvalidCredentials,
		Err:        errors.New("80090346: LdapErr: ..., data 80090346, v4563"),
	}
	if !IsChannelBindingRequired(cbErr) {
		t.Errorf("expected IsChannelBindingRequired to return true for SEC_E_BAD_BINDINGS")
	}
	if !IsChannelBindingRequired(fmt.Errorf("bind: %w", cbErr)) {
		t.Errorf("expected IsChannelBindingRequired to unwrap")
	}

	wrongPass := &Error{
		ResultCode: LDAPResultInvalidCredentials,
		Err:        errors.New("data 52e"),
	}
	if IsChannelBindingRequired(wrongPass) {
		t.Errorf("wrong-password (52e) must not be classified as channel-binding")
	}

	signing := &Error{
		ResultCode: LDAPResultStrongAuthRequired,
		Err:        errors.New("00002028: LdapErr: ..., data 0, v4563"),
	}
	if IsChannelBindingRequired(signing) {
		t.Errorf("strongerAuthRequired (signing) must not be classified as channel-binding")
	}

	if IsChannelBindingRequired(nil) {
		t.Errorf("nil error must return false")
	}
}

func TestClassifyBindError(t *testing.T) {
	cbErr := &Error{
		ResultCode: LDAPResultInvalidCredentials,
		Err:        errors.New("80090346: ..., data 80090346, v4563"),
	}
	signingErr := &Error{
		ResultCode: LDAPResultStrongAuthRequired,
		Err:        errors.New("00002028: ..., data 0, v4563"),
	}
	wrongPassErr := &Error{
		ResultCode: LDAPResultInvalidCredentials,
		Err:        errors.New("..., data 52e, v4563"),
	}
	lockedErr := &Error{
		ResultCode: LDAPResultInvalidCredentials,
		Err:        errors.New("..., data 775, v4563"),
	}
	opaqueCredErr := &Error{
		ResultCode: LDAPResultInvalidCredentials,
		Err:        errors.New("invalid credentials"),
	}
	unknownSubErr := &Error{
		ResultCode: LDAPResultInvalidCredentials,
		Err:        errors.New("..., data deadbeef, v4563"),
	}
	confidentialityErr := &Error{
		ResultCode: LDAPResultConfidentialityRequired,
		Err:        errors.New("00000005: LdapErr: ..."),
	}

	cases := []struct {
		name     string
		err      error
		overTLS  bool
		wantKind BindFailureKind
		wantSub  uint32
		wantDesc bool // expect non-empty Description
	}{
		{"SEC_E_BAD_BINDINGS over TLS", cbErr, true, BindFailureChannelBinding, 0, false},
		{"SEC_E_BAD_BINDINGS over plaintext", cbErr, false, BindFailureChannelBinding, 0, false},
		{"code 8 over TLS → CB", signingErr, true, BindFailureChannelBinding, 0, false},
		{"code 8 over plaintext → signing", signingErr, false, BindFailureSigning, 0, false},
		{"wrong password → credentials with detail", wrongPassErr, false, BindFailureCredentials, SubStatusInvalidCredentials, true},
		{"account locked → credentials with detail", lockedErr, false, BindFailureCredentials, SubStatusAccountLocked, true},
		{"wrapped credentials", fmt.Errorf("bind: %w", wrongPassErr), false, BindFailureCredentials, SubStatusInvalidCredentials, true},
		{"opaque code 49 → credentials, no detail", opaqueCredErr, false, BindFailureCredentials, 0, false},
		{"unknown substatus → credentials with hex but no description", unknownSubErr, false, BindFailureCredentials, 0xdeadbeef, false},
		{"confidentiality required → TLS needed", confidentialityErr, false, BindFailureConfidentialityRequired, 0, false},
		{"nil error", nil, false, BindFailureUnclassified, 0, false},
		{"non-ldap error", errors.New("network down"), false, BindFailureUnclassified, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyBindError(tc.err, tc.overTLS)
			if got.Kind != tc.wantKind {
				t.Fatalf("Kind = %v, want %v", got.Kind, tc.wantKind)
			}
			if got.SubStatus != tc.wantSub {
				t.Errorf("SubStatus = 0x%x, want 0x%x", got.SubStatus, tc.wantSub)
			}
			if (got.Description != "") != tc.wantDesc {
				t.Errorf("Description = %q, wantDesc=%v", got.Description, tc.wantDesc)
			}
		})
	}
}
