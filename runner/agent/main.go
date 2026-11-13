// Command agent is the Rovara function runner's in-sandbox agent. It runs as PID 1 (or under a
// minimal init) inside a gVisor sandbox, serves the AWS Lambda Runtime API on loopback for the
// function's runtime, and exchanges invocations with the worker over stdin and stdout (see
// PROTOCOL.md). Standard library only; Linux only.
//
//	agent [flags] [--] [runtime command [args...]]
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := hardenSelf(); err != nil {
		writeFrame(os.Stdout, fatalMsg{Type: "fatal", Message: "cannot make the agent non-dumpable: " + err.Error()})
		os.Exit(2)
	}
	// The runtime runs as the same user and can signal PID 1. Terminal stop signals are ignored
	// (SIGSTOP cannot be; see PROTOCOL.md).
	signal.Ignore(syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
	var cfg config
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	fs.StringVar(&cfg.Listen, "listen", defaultListen, "Runtime API address (loopback only; port 0 picks a free port)")
	fs.DurationVar(&cfg.InitTimeout, "init-timeout", defaultInitTimeout, "time the runtime may take to start polling for invocations")
	fs.IntVar(&cfg.RingBytes, "log-ring", defaultRingBytes, "bytes of runtime output kept")
	fs.IntVar(&cfg.UID, "uid", 0, "run the runtime as this uid (0: same user as the agent)")
	fs.IntVar(&cfg.GID, "gid", 0, "run the runtime with this gid")
	debug := fs.Bool("debug", false, "copy the runtime's output to the agent's stderr")
	version := fs.Bool("version", false, "print the version and exit")
	fs.Parse(os.Args[1:])
	if *version {
		fmt.Println("rovara-runner-agent", agentVersion, protoVersion)
		return
	}
	cfg.Cmd = fs.Args()
	if *debug {
		cfg.Debug = os.Stderr
	}
	if cfg.InitTimeout < time.Millisecond {
		cfg.InitTimeout = defaultInitTimeout
	}
	a := newAgent(cfg)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; a.Shutdown() }()
	os.Exit(a.run(os.Stdin, os.Stdout))
}
