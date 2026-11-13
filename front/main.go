// rovara-aws-front: a thin front that makes AWS Emulator look like Rovara's local AWS emulator from the outside.
//
// It listens on the run's address (plain HTTP, port 4566), answers the control paths the Cloud worker uses, keeps the
// request ledger, switches services off, and forwards every AWS API request to AWS Emulator, which it runs as a child on
// 127.0.0.1 (HTTPS, its own CA, signature checks off, telemetry off). Responses are rewritten so the run's code only ever
// sees ROVARA_AWS_BASE_URL.
package main

import (
	"context"
	"crypto/tls"
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
	if len(os.Args) > 1 && os.Args[1] == "runner-pipe" {
		// the worker's end: joins stdin and stdout to the front's runner socket (`docker exec -i <helper> <front> runner-pipe`)
		os.Exit(runnerPipeMain(os.Args[2:], os.Getenv))
	}
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
	// The TLS listener's certificates are checked BEFORE anything listens: a leaf that does not verify against the run CA stops the front.
	var tlsRaw net.Listener
	var leaves *leafSet
	if cfg.TLS != nil {
		if leaves, err = loadLeafSet(cfg.TLS, time.Now()); err != nil {
			engine.Stop()
			fmt.Fprintf(os.Stderr, "Refusing to start: the TLS listener's certificates are not the run CA's: %v\n", err)
			os.Exit(1)
		}
		if tlsRaw, err = net.Listen("tcp", cfg.TLS.Addr); err != nil {
			engine.Stop()
			fmt.Fprintf(os.Stderr, "cannot listen on %s: %v\n", cfg.TLS.Addr, err)
			os.Exit(1)
		}
		cfg.RunCARoots, cfg.SelfTLSAddr = leaves.root, tlsRaw.Addr().String()
	}
	srv := newServer(cfg, engine)
	if err := srv.startRunner(); err != nil {
		engine.Stop()
		fmt.Fprintf(os.Stderr, "the function runner did not start: %s\n", sanitizeErr(err))
		os.Exit(1)
	}
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
	h2c := enableH2C(hs)
	log.Printf("rovara-aws-front %s listening on %s (h2c %v)", version, ln.Addr(), h2c)
	var ts *http.Server
	if tlsRaw != nil {
		ts = newTLSServer(srv, leaves, 15*time.Second)
		go ts.Serve(tls.NewListener(tlsRaw, leaves.tlsConfig()))
		log.Printf("TLS listener on %s for %d names (run CA leaves)", tlsRaw.Addr(), len(leaves.serverNames()))
	}

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
	if srv.runner != nil {
		srv.runner.close()
	}
	if ts != nil {
		ts.Shutdown(ctx)
	}
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
