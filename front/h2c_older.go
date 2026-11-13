//go:build !go1.24

package main

import "net/http"

// enableH2C is a no-op before Go 1.24 (see h2c_go124.go).
func enableH2C(hs *http.Server) bool { return false }
