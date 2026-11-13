//go:build go1.24

package main

import "net/http"

// enableH2C lets the front's cleartext port speak HTTP/2 with prior knowledge (h2c) as well as HTTP/1.1, which Go 1.24 can do with no
// other package. The AWS SDK for JavaScript v3 sends every Bedrock runtime call over HTTP/2 (its client always uses its HTTP/2 request
// handler), also to an http:// endpoint such as http://aws:4566, and a server that only speaks HTTP/1.1 answers it with a protocol
// error. An HTTP/1.1 client is unaffected: the server tells the two apart by the connection preface. The image builds with a newer Go
// (Containerfile.engine); a build with an older one has no h2c (h2c_older.go) and Node's Bedrock runtime client then needs an HTTP/1.1
// request handler.
func enableH2C(hs *http.Server) bool {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	hs.Protocols = p
	return true
}
