package ldap

import "fmt"

// DetectSigningRequired probes the server with an NTLM bind that does NOT
// negotiate sign/seal and reports whether the server requires LDAP signing.
//
// Return values:
//   - (false, nil): signing is NOT required. The probe bind succeeded, then
//     the connection's authenticated state was cleared via an anonymous
//     simple bind. The connection is left open and unauthenticated; the
//     caller can issue a fresh Bind on it.
//   - (true,  nil): signing IS required. The probe bind was rejected by the
//     server with strongerAuthRequired (LDAP code 8). The connection is
//     left open and unauthenticated; the caller can retry with
//     SASLSecuritySign or SASLSecuritySeal.
//   - (_, err) with err != nil: detection was inconclusive. Ignore the bool
//     return — the probe failed for a reason other than the signing policy
//     (bad credentials, network error, server returned a different result
//     code, etc.).
//
// The probe submits the supplied credentials. If they are wrong the failed
// bind counts toward account lockout policy on most directory servers; use
// a service or test account when in doubt.
//
// This function only applies to non-TLS connections. Over TLS the LDAP
// integrity policy is not enforced (signing is provided by TLS itself), and
// LDAP code 8 instead indicates the channel-binding policy — a different
// thing this function does not detect.
func (l *Conn) DetectSigningRequired(domain, username, password string) (bool, error) {
	return l.detectNTLMSigningRequired(&NTLMBindRequest{
		Domain:       domain,
		Username:     username,
		Password:     password,
		SASLSecurity: SASLSecurityNone,
	})
}

// DetectSigningRequiredWithHash is like DetectSigningRequired but
// authenticates using an NTLM hash instead of a plaintext password.
// Same return-value contract.
func (l *Conn) DetectSigningRequiredWithHash(domain, username, hash string) (bool, error) {
	return l.detectNTLMSigningRequired(&NTLMBindRequest{
		Domain:       domain,
		Username:     username,
		Hash:         hash,
		SASLSecurity: SASLSecurityNone,
	})
}

func (l *Conn) detectNTLMSigningRequired(req *NTLMBindRequest) (bool, error) {
	if l.isTLS {
		return false, fmt.Errorf("ldap: signing detection not applicable over TLS (TLS already provides integrity)")
	}
	_, err := l.NTLMChallengeBind(req)
	return interpretSigningProbe(l, err)
}

// DetectSigningRequiredKerberos probes the server with a GSSAPI/Kerberos
// bind that does NOT negotiate sign/seal and reports whether the server
// requires LDAP signing. The provided client is used for the AP-REQ
// exchange; servicePrincipal is the target SPN (e.g. "ldap/dc01.example.com").
//
// Return values follow the same contract as DetectSigningRequired:
//   - (false, nil): signing is NOT required. Connection left unauthenticated.
//   - (true,  nil): signing IS required. Connection left unauthenticated.
//   - (_, err) with err != nil: inconclusive — bool return must be ignored.
//
// As with the NTLM variant, this only applies to non-TLS connections.
//
// Note: GSSAPIBindRequest deletes the security context on the client when
// the call returns. Callers who want to follow up with a real signed bind
// using Kerberos must construct a fresh GSSAPIClient (or call back into
// their KDC) for that bind.
func (l *Conn) DetectSigningRequiredKerberos(client GSSAPIClient, servicePrincipal string) (bool, error) {
	if l.isTLS {
		return false, fmt.Errorf("ldap: signing detection not applicable over TLS (TLS already provides integrity)")
	}
	err := l.GSSAPIBindRequest(client, &GSSAPIBindRequest{
		ServicePrincipalName: servicePrincipal,
		SASLSecurity:         SASLSecurityNone,
	})
	return interpretSigningProbe(l, err)
}

// interpretSigningProbe maps a probe-bind error into the (required, err)
// return contract. On success it clears authenticated state via an
// anonymous bind so callers receive a connection in a known unauthenticated
// state regardless of whether signing was required.
func interpretSigningProbe(l *Conn, bindErr error) (bool, error) {
	if bindErr == nil {
		// Probe bind succeeded → signing is not required. Drop the
		// authenticated state. Per RFC 4511 §4.2.1 the server clears
		// prior auth on receipt of any bind request, so even if the
		// anonymous bind is rejected by policy the connection ends up
		// unauthenticated. Discard the rebind error.
		_ = l.UnauthenticatedBind("")
		return false, nil
	}
	if IsErrorWithCode(bindErr, LDAPResultStrongAuthRequired) {
		return true, nil
	}
	return false, bindErr
}
