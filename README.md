[![GoDoc](https://pkg.go.dev/badge/github.com/jfjallid/ldap/v3.svg)](https://pkg.go.dev/github.com/jfjallid/ldap/v3)

# Basic LDAP v3 functionality for the GO programming language.

Forked from [github.com/go-ldap/ldap](https://github.com/go-ldap/ldap).

The library implements the following specifications:

- https://datatracker.ietf.org/doc/html/rfc4511 for basic operations
- https://datatracker.ietf.org/doc/html/rfc3062 for password modify operation
- https://datatracker.ietf.org/doc/html/rfc4514 for distinguished names parsing
- https://datatracker.ietf.org/doc/html/rfc4517 for postal address parsing
- https://datatracker.ietf.org/doc/html/rfc4533 for Content Synchronization Operation
- https://datatracker.ietf.org/doc/html/rfc5929 for TLS channel binding (`tls-server-end-point`)
- https://datatracker.ietf.org/doc/html/draft-armijo-ldap-treedelete-02 for Tree Delete Control
- https://datatracker.ietf.org/doc/html/rfc2891 for Server Side Sorting of Search Results
- https://datatracker.ietf.org/doc/html/rfc4532 for WhoAmI requests

## Features:

- Connecting to LDAP server (non-TLS, TLS, STARTTLS, through a custom dialer)
- Bind Requests / Responses (Simple Bind, GSSAPI, SASL)
- NTLM bind with TLS channel binding (Extended Protection for Authentication, RFC 5929)
- Kerberos / GSSAPI bind with TLS channel binding
- SASL sign/seal security layer for NTLM and Kerberos binds
- Raw binary attribute values via `AttributeBytes` / `AddBytes` / `DeleteBytes` / `ReplaceBytes`
- "Who Am I" Requests / Responses
- Search Requests / Responses (normal, paging and asynchronous)
- Modify Requests / Responses
- Add Requests / Responses
- Delete Requests / Responses
- Modify DN Requests / Responses
- Unbind Requests / Responses
- Password Modify Requests / Responses
- Content Synchronization Requests / Responses
- LDAPv3 Filter Compile / Decompile
- Server Side Sorting of Search Results
- LDAPv3 Extended Operations
- LDAPv3 Control Support

## Go Modules:

`go get github.com/jfjallid/ldap/v3`

## Contributing:

Bug reports and pull requests are welcome!

Before submitting a pull request, please make sure tests and verification scripts pass:

```
# Setup local directory server using Docker or Podman
make local-server

# Run gofmt, go vet and go test
cd ./v3
make -f ../Makefile

# (Optionally) Stop and delete the directory server container afterwards
cd ..
make stop-local-server
```

---

The Go gopher was designed by Renee French. (http://reneefrench.blogspot.com/)
The design is licensed under the Creative Commons 3.0 Attributions license.
Read this article for more details: http://blog.golang.org/gopher
