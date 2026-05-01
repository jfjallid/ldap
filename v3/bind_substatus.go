package ldap

import (
	"errors"
	"regexp"
	"strconv"
)

// AD bind-failure substatuses. Active Directory returns LDAPResult 49
// (InvalidCredentials) for almost every authentication failure and embeds
// the real reason as a hex "data" field inside the diagnosticMessage, e.g.:
//
//	80090346: LdapErr: DSID-0C09075C, comment: AcceptSecurityContext error,
//	data 80090346, v4563
//
// The constants below cover the values most useful for diagnostics. The
// SEC_E_* values come from the SSPI status set; the small numeric codes are
// the AD-specific NTSTATUS-like substatuses that AcceptSecurityContext
// surfaces for password / account problems.
const (
	// SSPI failures.
	SubStatusBadBindings   uint32 = 0x80090346 // SEC_E_BAD_BINDINGS — channel binding mismatch / required.
	SubStatusInvalidToken  uint32 = 0x80090308 // SEC_E_INVALID_TOKEN
	SubStatusTargetUnknown uint32 = 0x80090303 // SEC_E_TARGET_UNKNOWN
	SubStatusLogonDenied   uint32 = 0x8009030C // SEC_E_LOGON_DENIED — generic AcceptSecurityContext rejection.

	// AD account / credential reasons. These are the values you get from
	// `data <hex>` for password/account state failures.
	SubStatusUserNotFound        uint32 = 0x525
	SubStatusInvalidCredentials  uint32 = 0x52e
	SubStatusNotPermittedToLogon uint32 = 0x530
	SubStatusPasswordExpired     uint32 = 0x532
	SubStatusAccountDisabled     uint32 = 0x533
	SubStatusAccountExpired      uint32 = 0x701
	SubStatusMustResetPassword   uint32 = 0x773
	SubStatusAccountLocked       uint32 = 0x775
)

// SubStatusDescription contains short human-readable descriptions for the
// substatuses defined above. Keys absent from the map fall through to the
// raw hex value when formatted by callers.
var SubStatusDescription = map[uint32]string{
	SubStatusBadBindings:         "channel binding mismatch (SEC_E_BAD_BINDINGS) — server requires LDAP channel binding",
	SubStatusInvalidToken:        "invalid security token (SEC_E_INVALID_TOKEN)",
	SubStatusTargetUnknown:       "target unknown (SEC_E_TARGET_UNKNOWN)",
	SubStatusLogonDenied:         "logon denied (SEC_E_LOGON_DENIED)",
	SubStatusUserNotFound:        "user not found",
	SubStatusInvalidCredentials:  "invalid credentials (wrong password)",
	SubStatusNotPermittedToLogon: "not permitted to logon at this time",
	SubStatusPasswordExpired:     "password expired",
	SubStatusAccountDisabled:     "account disabled",
	SubStatusAccountExpired:      "account expired",
	SubStatusMustResetPassword:   "user must reset password",
	SubStatusAccountLocked:       "account locked",
}

// dataFieldPattern extracts the substatus from an AD diagnosticMessage.
// AD always uses the literal "data " prefix followed by a hex value.
var dataFieldPattern = regexp.MustCompile(`(?i)\bdata\s+([0-9a-f]{1,8})\b`)

// ExtractBindSubStatus parses Active Directory's diagnosticMessage out of an
// LDAP bind error and returns the SSPI / NTSTATUS-like substatus encoded in
// the "data <hex>" field. ok is false when err is not an *Error or the
// diagnostic message does not carry a recognisable data field — for example,
// non-AD servers, or AD errors that aren't bind failures.
func ExtractBindSubStatus(err error) (status uint32, ok bool) {
	if err == nil {
		return 0, false
	}
	var ldapErr *Error
	if !errors.As(err, &ldapErr) || ldapErr.Err == nil {
		return 0, false
	}
	m := dataFieldPattern.FindStringSubmatch(ldapErr.Err.Error())
	if m == nil {
		return 0, false
	}
	v, perr := strconv.ParseUint(m[1], 16, 32)
	if perr != nil {
		return 0, false
	}
	return uint32(v), true
}

// IsChannelBindingRequired reports whether err is an AD bind rejection
// caused by a missing or mismatched TLS channel binding token. AD signals
// this with LDAPResult 49 (InvalidCredentials) plus diagnosticMessage
// substatus 0x80090346 (SEC_E_BAD_BINDINGS).
//
// This is the canonical signal that the server enforces the LDAP
// channel-binding policy on TLS-protected binds. It is distinct from
// IsSigningRequired, which detects the integrity (signing) policy on
// non-TLS binds via LDAPResult 8 (StrongAuthRequired).
func IsChannelBindingRequired(err error) bool {
	if !IsErrorWithCode(err, LDAPResultInvalidCredentials) {
		return false
	}
	status, ok := ExtractBindSubStatus(err)
	return ok && status == SubStatusBadBindings
}

// IsSigningRequired reports whether err is an LDAP strongerAuthRequired
// (code 8) response from a bind that did not negotiate signing. On a
// non-TLS connection this is the canonical signal that the server enforces
// the LDAP integrity policy. Over TLS the same code 8 instead indicates
// the channel-binding policy, so callers must verify the connection is
// non-TLS before drawing the "signing required" conclusion from this.
func IsSigningRequired(err error) bool {
	return IsErrorWithCode(err, LDAPResultStrongAuthRequired)
}

// BindFailureKind classifies an AD bind failure by the policy or condition
// that caused it. The zero value (BindFailureUnclassified) indicates no
// recognised AD signal; callers should fall back to printing the raw error.
type BindFailureKind int

const (
	BindFailureUnclassified BindFailureKind = iota
	// BindFailureChannelBinding means the server enforces its LDAP
	// channel-binding policy. Triggered by either:
	//  - LDAPResult 49 (InvalidCredentials) + SEC_E_BAD_BINDINGS, or
	//  - LDAPResult 8 (StrongAuthRequired) on a TLS-protected connection
	//    (some AD configurations surface CB enforcement this way).
	BindFailureChannelBinding
	// BindFailureSigning means the server enforces its LDAP signing
	// (integrity) policy on non-TLS connections (LDAPResult 8 on plaintext).
	BindFailureSigning
	// BindFailureConfidentialityRequired means the server requires a
	// confidential (TLS) connection for this operation. Signalled by
	// LDAPResult 13 (confidentialityRequired); the caller should retry
	// over TLS or StartTLS.
	BindFailureConfidentialityRequired
	// BindFailureCredentials means the server returned LDAPResult 49
	// (InvalidCredentials). This covers the full range of AD authentication
	// rejections — wrong password, user not found, account locked,
	// password expired, account disabled, etc. AD encodes the specific
	// reason in a "data <hex>" substatus on the diagnosticMessage; when
	// present and recognised, SubStatus and Description carry the detail.
	BindFailureCredentials
)

// BindFailure is a classified bind failure produced by ClassifyBindError.
type BindFailure struct {
	Kind        BindFailureKind
	SubStatus   uint32 // AD substatus (e.g. SubStatusAccountLocked); 0 when absent
	Description string // human description for known SubStatus values; empty otherwise
}

// ClassifyBindError categorises an AD bind error by the policy or condition
// it represents. overTLS must reflect whether the underlying connection is
// TLS-protected (including StartTLS) because LDAPResult 8 carries different
// meanings on TLS vs plaintext.
//
// Returns a zero-value BindFailure (Kind == BindFailureUnclassified) for
// nil or unrecognised errors. Callers typically switch on Kind to format a
// caller-specific message (e.g. with their own CLI flag names) and fall
// through to printing the raw err on Unclassified.
func ClassifyBindError(err error, overTLS bool) BindFailure {
	if err == nil {
		return BindFailure{}
	}
	if IsChannelBindingRequired(err) {
		return BindFailure{Kind: BindFailureChannelBinding}
	}
	if IsSigningRequired(err) {
		if overTLS {
			return BindFailure{Kind: BindFailureChannelBinding}
		}
		return BindFailure{Kind: BindFailureSigning}
	}
	if IsErrorWithCode(err, LDAPResultConfidentialityRequired) {
		return BindFailure{Kind: BindFailureConfidentialityRequired}
	}
	if IsErrorWithCode(err, LDAPResultInvalidCredentials) {
		f := BindFailure{Kind: BindFailureCredentials}
		if status, ok := ExtractBindSubStatus(err); ok {
			f.SubStatus = status
			f.Description = SubStatusDescription[status]
		}
		return f
	}
	return BindFailure{}
}
