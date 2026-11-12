// rovara-aws-front: a thin front that makes AWS Emulator look like Rovara's local AWS emulator from the outside.
//
// It listens on the run's address (plain HTTP, port 4566), answers the control paths the Cloud worker uses, keeps the
// request ledger, switches services off, and forwards every AWS API request to AWS Emulator, which it runs as a child on
// 127.0.0.1 (HTTPS, its own CA, signature checks off, telemetry off). Responses are rewritten so the run's code only ever
// sees ROVARA_AWS_BASE_URL.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	log.SetFlags(0)
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	if cfg.DevOpen && cfg.Token == "" {
		log.Printf("DEVELOPMENT SWITCH ON: %s=1 opens every /_rovara control path (reset, seed, ledger) to anyone who can reach this port. Never set it in a run or an image.", envDevOpen)
	} else if cfg.DevOpen {
		log.Printf("%s=1 is set, but a control token is configured, so the token is still required. Never set the development switch in a run.", envDevOpen)
	}
	engine := newEngine(cfg.EngineBin, cfg.WorkDir)
	if err := engine.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "the emulator engine did not start: %s\n", sanitizeErr(err))
		os.Exit(1)
	}
	srv := newServer(cfg, engine)
	ln, err := net.Listen("tcp", net.JoinHostPort(trimBrackets(cfg.Host), strconv.Itoa(cfg.Port)))
	if err != nil {
		engine.Stop()
		fmt.Fprintf(os.Stderr, "cannot listen on %s:%d: %v\n", cfg.Host, cfg.Port, err)
		os.Exit(1)
	}
	hs := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 15 * time.Second,
		// a whole request, headers and body: generous, since a big upload is one request; no WriteTimeout, so a long poll is never cut
		ReadTimeout:    30 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 1 << 20,
		ErrorLog:       log.New(discardWriter{}, "", 0),
	}
	log.Printf("rovara-aws-front %s listening on %s", version, ln.Addr())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case <-stop:
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("the server stopped: %v", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hs.Shutdown(ctx)
	engine.Stop()
}

func trimBrackets(h string) string {
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		return h[1 : len(h)-1]
	}
	return h
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
